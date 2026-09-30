package identityprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"gorm.io/gorm"

	"github.com/pocket-id/pocket-id/backend/internal/appconfig"
	"github.com/pocket-id/pocket-id/backend/internal/apperror"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
)

// authenticationMethodFederated identifies a sign-in through an external identity provider in the "amr" claim
// It's the value Microsoft Entra ID uses for federated authentication, as RFC 8176 does not define one
const authenticationMethodFederated = "fed"

// accountSettingsPath is where users manage their linked accounts, and where the link flow returns to
const accountSettingsPath = "/settings/account"

// StartLogin prepares a sign-in with an identity provider
// It returns the authorization URL the browser has to be sent to and the encrypted state to store in a cookie
func (s *Service) StartLogin(ctx context.Context, providerID, redirect string) (authURL string, stateCookie string, err error) {
	return s.start(ctx, providerID, loginState{
		Mode:     flowModeLogin,
		Redirect: sanitizeRedirect(redirect),
	})
}

// StartLink prepares linking an external account to the signed-in user
// The user ID is stored in the state, so the callback can check the same user is still signed in
func (s *Service) StartLink(ctx context.Context, providerID, userID string) (authURL string, stateCookie string, err error) {
	return s.start(ctx, providerID, loginState{
		Mode:     flowModeLink,
		Redirect: accountSettingsPath,
		UserID:   userID,
	})
}

func (s *Service) start(ctx context.Context, providerID string, state loginState) (string, string, error) {
	// Load the provider and its endpoints
	provider, err := s.getEnabled(ctx, providerID)
	if err != nil {
		return "", "", err
	}
	document, err := s.rp.Discover(ctx, provider.Issuer)
	if err != nil {
		return "", "", apperror.IdentityProviderUnreachable(err)
	}

	// Generate the values that bind the callback to this browser: the state against login CSRF, the nonce against ID token replay and the PKCE verifier against code interception
	state.ProviderID = provider.ID
	state.State, err = utils.GenerateRandomAlphanumericString(32)
	if err != nil {
		return "", "", err
	}
	state.Nonce, err = utils.GenerateRandomAlphanumericString(32)
	if err != nil {
		return "", "", err
	}
	state.CodeVerifier = oauth2.GenerateVerifier()
	state.ExpiresAt = time.Now().Add(loginStateTTL)

	encodedState, err := s.states.Encode(state)
	if err != nil {
		return "", "", err
	}

	// Build the authorization request with PKCE, which also protects confidential clients
	authURL := oauthConfig(provider, document, s.callbackURL).AuthCodeURL(
		state.State,
		oauth2.S256ChallengeOption(state.CodeVerifier),
		oauth2.SetAuthURLParam("nonce", state.Nonce),
	)

	return authURL, encodedState, nil
}

// callbackInput is what the callback handler collected from the request
type callbackInput struct {
	State       string
	Code        string
	Issuer      string
	Error       string
	StateCookie string
	// SignedInUserID is the user of the current session, if any, which must match the user that started a link flow
	SignedInUserID string
	IPAddress      string
	UserAgent      string
}

// callbackResult tells the handler where to send the browser and, for a sign-in, which session to create
// Mode and Redirect are also set when an error is returned, as soon as the state could be decrypted
type callbackResult struct {
	Mode        flowMode
	Redirect    string
	User        model.User
	AccessToken string
}

// HandleCallback completes a sign-in or link flow when the identity provider redirects the browser back to Pocket ID
func (s *Service) HandleCallback(ctx context.Context, dbConfig *appconfig.AppConfigModel, input callbackInput) (callbackResult, error) {
	result := callbackResult{Mode: flowModeLogin, Redirect: defaultRedirect}

	// Restore the state stored in the browser when the flow started
	state, err := s.states.Decode(input.StateCookie, input.State)
	if state.Mode != "" {
		result.Mode = state.Mode
		result.Redirect = sanitizeRedirect(state.Redirect)
	}
	if err != nil {
		return result, apperror.IdentityProviderStateInvalid(err)
	}

	// The user may have cancelled the sign-in, or the provider rejected the request
	if input.Error != "" {
		return result, apperror.IdentityProviderReturnedError(sanitizeErrorCode(input.Error))
	}
	if input.Code == "" {
		return result, apperror.IdentityProviderLoginFailed(errors.New("callback does not contain an authorization code"))
	}

	// Load the provider the flow was started with
	provider, err := s.getEnabled(ctx, state.ProviderID)
	if err != nil {
		return result, err
	}
	document, err := s.rp.Discover(ctx, provider.Issuer)
	if err != nil {
		return result, apperror.IdentityProviderUnreachable(err)
	}

	// Providers supporting RFC 9207 name themselves in the response, which uncovers mix-up attacks since all providers share the callback URL
	if input.Issuer != "" && input.Issuer != document.Issuer {
		return result, apperror.IdentityProviderLoginFailed(fmt.Errorf("authorization response issuer %q does not match %q", input.Issuer, document.Issuer))
	}

	// Redeem the code and verify who the provider says the user is
	identity, err := s.authenticate(ctx, provider, document, input.Code, state)
	if err != nil {
		return result, err
	}

	switch state.Mode {
	case flowModeLink:
		// The session must still belong to the user who started linking, otherwise the external account would be linked to someone else
		if input.SignedInUserID == "" || input.SignedInUserID != state.UserID {
			return result, apperror.IdentityProviderSessionChanged()
		}

		err = s.linkAccount(ctx, provider, identity, state.UserID, input.IPAddress, input.UserAgent)
		return result, err

	case flowModeLogin:
		result.User, result.AccessToken, err = s.signIn(ctx, dbConfig, provider, identity, input.IPAddress, input.UserAgent)
		return result, err

	default:
		return result, apperror.IdentityProviderStateInvalid(fmt.Errorf("unknown flow mode %q", state.Mode))
	}
}

// authenticate exchanges the authorization code and returns the verified identity of the external account
func (s *Service) authenticate(ctx context.Context, provider IdentityProvider, document discoveryDocument, code string, state loginState) (externalIdentity, error) {
	// Redeem the authorization code with the PKCE verifier
	idToken, accessToken, err := s.rp.ExchangeCode(ctx, oauthConfig(provider, document, s.callbackURL), code, state.CodeVerifier)
	if err != nil {
		return externalIdentity{}, apperror.IdentityProviderLoginFailed(err)
	}

	// The ID token is the only source of truth for the subject, since it's signed by the provider and bound to this flow by the nonce
	claims, err := s.rp.VerifyIDToken(ctx, document, provider.ClientID, idToken, state.Nonce)
	if err != nil {
		return externalIdentity{}, apperror.IdentityProviderLoginFailed(err)
	}

	// Many providers only return profile claims from the userinfo endpoint, so failing to load them is not fatal
	userinfo, err := s.rp.FetchUserinfo(ctx, document, accessToken)
	if err != nil {
		slog.WarnContext(ctx, "Failed to load userinfo from identity provider", slog.String("identityProvider", provider.Name), slog.Any("error", err))
		userinfo = nil
	}

	identity, err := newExternalIdentity(claims, userinfo)
	if err != nil {
		return externalIdentity{}, apperror.IdentityProviderLoginFailed(err)
	}

	return identity, nil
}

// sanitizeErrorCode keeps only the characters OAuth 2.0 allows in error codes, since the value comes from the query string
func sanitizeErrorCode(code string) string {
	code = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return -1
	}, code)

	if len(code) > 64 {
		code = code[:64]
	}
	if code == "" {
		code = "unknown_error"
	}

	return code
}

// signIn resolves the local user of an external account and issues a session for it
func (s *Service) signIn(ctx context.Context, dbConfig *appconfig.AppConfigModel, provider IdentityProvider, identity externalIdentity, ipAddress, userAgent string) (model.User, string, error) {
	tx := s.db.Begin()
	defer func() {
		tx.Rollback()
	}()

	// Find the user linked to the external account, linking or creating one if the provider allows it
	user, link, created, err := s.resolveUser(ctx, tx, dbConfig, provider, identity, ipAddress, userAgent)
	if err != nil {
		return model.User{}, "", err
	}
	if user.Disabled {
		return model.User{}, "", apperror.UserDisabled()
	}

	// Keep the profile in sync with the provider when it's the source of truth for the user's details
	updated := false
	if !created && provider.AutoUpdateUsers {
		updated, err = s.updateUserProfile(ctx, tx, &user, identity)
		if err != nil {
			return model.User{}, "", err
		}
	}

	// Remember when and with which email address the link was last used, so users can recognize it
	err = tx.
		WithContext(ctx).
		Model(&Link{}).
		Where("id = ?", link.ID).
		Updates(map[string]any{
			"last_used_at": datatype.DateTime(time.Now()),
			"email":        identity.Email,
		}).
		Error
	if err != nil {
		return model.User{}, "", fmt.Errorf("failed to update link: %w", err)
	}

	// Issue the session and record the sign-in
	accessToken, err := s.signer.GenerateAccessToken(user, authenticationMethodFederated, dbConfig.SessionDuration.AsDurationMinutes())
	if err != nil {
		return model.User{}, "", err
	}

	s.auditLog.CreateSignInEventWithEmail(ctx, model.AuditLogEventIdentityProviderSignIn, model.AuditLogData{
		"identityProvider": provider.Name,
	}, ipAddress, userAgent, user.ID, tx, dbConfig.EmailLoginNotificationEnabled.IsTrue())

	err = tx.Commit().Error
	if err != nil {
		return model.User{}, "", err
	}

	// Created and updated users have to be provisioned to the SCIM service providers
	if (created || updated) && s.scimSync != nil {
		s.scimSync.ScheduleSync(ctx)
	}

	return user, accessToken, nil
}

// resolveUser returns the local user for an external account, along with its link and whether the user was just created
func (s *Service) resolveUser(ctx context.Context, tx *gorm.DB, dbConfig *appconfig.AppConfigModel, provider IdentityProvider, identity externalIdentity, ipAddress, userAgent string) (model.User, Link, bool, error) {
	// An existing link always wins
	link, found, err := findLink(ctx, tx, provider.ID, identity.Subject)
	if err != nil {
		return model.User{}, Link{}, false, err
	}
	if found {
		var user model.User
		err = tx.WithContext(ctx).Where("id = ?", link.UserID).First(&user).Error
		if err != nil {
			return model.User{}, Link{}, false, fmt.Errorf("failed to load linked user: %w", err)
		}
		return user, link, false, nil
	}

	// Link the external account to the user with the same email address, but only if the provider verified that the address belongs to the account
	if provider.AutoLinkUsers && identity.Email != nil && identity.EmailVerified {
		var user model.User
		err = tx.
			WithContext(ctx).
			Where("LOWER(email) = LOWER(?)", *identity.Email).
			First(&user).
			Error
		if err == nil {
			link, err = s.createLink(ctx, tx, provider, identity, user.ID, ipAddress, userAgent)
			if err != nil {
				return model.User{}, Link{}, false, err
			}
			return user, link, false, nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return model.User{}, Link{}, false, err
		}
	}

	// Create a new user for the external account
	if provider.AutoCreateUsers {
		user, err := s.createUser(ctx, tx, dbConfig, identity)
		if err != nil {
			return model.User{}, Link{}, false, err
		}

		s.auditLog.Create(ctx, model.AuditLogEventAccountCreated, ipAddress, userAgent, user.ID, model.AuditLogData{
			"method":           "identity_provider",
			"identityProvider": provider.Name,
		}, tx)

		link, err = s.createLink(ctx, tx, provider, identity, user.ID, ipAddress, userAgent)
		if err != nil {
			return model.User{}, Link{}, false, err
		}
		return user, link, true, nil
	}

	return model.User{}, Link{}, false, apperror.IdentityProviderAccountNotLinked()
}

// linkAccount links an external account to a user who is already signed in
func (s *Service) linkAccount(ctx context.Context, provider IdentityProvider, identity externalIdentity, userID, ipAddress, userAgent string) error {
	tx := s.db.Begin()
	defer func() {
		tx.Rollback()
	}()

	// An external account can only belong to one user, while linking it again to the same user is harmless
	link, found, err := findLink(ctx, tx, provider.ID, identity.Subject)
	if err != nil {
		return err
	}
	if found {
		if link.UserID != userID {
			return apperror.IdentityProviderExternalAccountAlreadyLinked()
		}
		return nil
	}

	_, err = s.createLink(ctx, tx, provider, identity, userID, ipAddress, userAgent)
	if err != nil {
		return err
	}

	return tx.Commit().Error
}

func findLink(ctx context.Context, tx *gorm.DB, providerID, subject string) (Link, bool, error) {
	var link Link
	err := tx.
		WithContext(ctx).
		Where("identity_provider_id = ? AND subject = ?", providerID, subject).
		First(&link).
		Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Link{}, false, nil
	} else if err != nil {
		return Link{}, false, err
	}

	return link, true, nil
}

// createLink stores a new link and records it in the audit log
func (s *Service) createLink(ctx context.Context, tx *gorm.DB, provider IdentityProvider, identity externalIdentity, userID, ipAddress, userAgent string) (Link, error) {
	// A user can be linked to only one account per provider, which is checked upfront since a failed insert would abort a Postgres transaction
	var count int64
	err := tx.
		WithContext(ctx).
		Model(&Link{}).
		Where("user_id = ? AND identity_provider_id = ?", userID, provider.ID).
		Count(&count).
		Error
	if err != nil {
		return Link{}, err
	}
	if count > 0 {
		return Link{}, apperror.IdentityProviderUserAlreadyLinked()
	}

	link := Link{
		UserID:             userID,
		IdentityProviderID: provider.ID,
		Subject:            identity.Subject,
		Email:              identity.Email,
		LastUsedAt:         new(datatype.DateTime(time.Now())),
	}
	err = tx.WithContext(ctx).Create(&link).Error
	if err != nil {
		return Link{}, fmt.Errorf("failed to create link: %w", err)
	}

	s.auditLog.Create(ctx, model.AuditLogEventIdentityProviderLinked, ipAddress, userAgent, userID, model.AuditLogData{
		"identityProvider": provider.Name,
	}, tx)

	return link, nil
}

// createUser creates a local user from the profile of an external account
func (s *Service) createUser(ctx context.Context, tx *gorm.DB, dbConfig *appconfig.AppConfigModel, identity externalIdentity) (model.User, error) {
	if identity.Email == nil && dbConfig.RequireUserEmail.IsTrue() {
		return model.User{}, apperror.IdentityProviderEmailRequired()
	}

	// An existing account with the same email address is never taken over implicitly, the user has to link it themselves
	if identity.Email != nil {
		inUse, err := emailInUse(ctx, tx, *identity.Email, "")
		if err != nil {
			return model.User{}, err
		}
		if inUse {
			return model.User{}, apperror.IdentityProviderEmailInUse()
		}
	}

	username, err := uniqueUsername(ctx, tx, identity.username())
	if err != nil {
		return model.User{}, err
	}

	firstName, lastName, displayName := identity.names()
	return s.userCreator.CreateUserInternal(ctx, dbConfig, dto.UserCreateDto{
		Username:      username,
		Email:         identity.Email,
		EmailVerified: identity.Email != nil && (identity.EmailVerified || dbConfig.EmailsVerified.IsTrue()),
		FirstName:     firstName,
		LastName:      lastName,
		DisplayName:   displayName,
	}, false, tx)
}

// updateUserProfile copies the profile of the external account to the user and reports whether anything changed
// LDAP users are skipped, since the LDAP sync owns their profile
func (s *Service) updateUserProfile(ctx context.Context, tx *gorm.DB, user *model.User, identity externalIdentity) (bool, error) {
	if user.LdapID != nil {
		return false, nil
	}

	changed := false
	setIfChanged := func(field *string, value string) {
		if value != "" && *field != value {
			*field = value
			changed = true
		}
	}

	// Only overwrite names the provider actually returned, so a provider that omits them does not blank the profile
	firstName, lastName, displayName := identity.names()
	setIfChanged(&user.FirstName, firstName)
	setIfChanged(&user.LastName, lastName)
	setIfChanged(&user.DisplayName, displayName)

	// The email address is only taken over when no other user has it, since it must be unique
	if identity.Email != nil && (user.Email == nil || !strings.EqualFold(*user.Email, *identity.Email)) {
		inUse, err := emailInUse(ctx, tx, *identity.Email, user.ID)
		if err != nil {
			return false, err
		}
		if inUse {
			slog.WarnContext(ctx, "Not updating the email address from the identity provider, since it's used by another user", slog.String("userID", user.ID))
		} else {
			user.Email = new(*identity.Email)
			user.EmailVerified = identity.EmailVerified
			changed = true
		}
	}

	if !changed {
		return false, nil
	}

	user.UpdatedAt = new(datatype.DateTime(time.Now()))
	err := tx.
		WithContext(ctx).
		Model(user).
		Select("first_name", "last_name", "display_name", "email", "email_verified", "updated_at").
		Updates(user).
		Error
	if err != nil {
		return false, fmt.Errorf("failed to update user from identity provider: %w", err)
	}

	return true, nil
}

// emailInUse reports whether another user than excludeUserID has the email address, ignoring case
func emailInUse(ctx context.Context, tx *gorm.DB, email, excludeUserID string) (bool, error) {
	var count int64
	err := tx.
		WithContext(ctx).
		Model(&model.User{}).
		Where("LOWER(email) = LOWER(?) AND id != ?", email, excludeUserID).
		Count(&count).
		Error
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// uniqueUsername returns the base username, or the first free variant of it with a numeric suffix
func uniqueUsername(ctx context.Context, tx *gorm.DB, base string) (string, error) {
	for i := 1; i <= 100; i++ {
		candidate := base
		if i > 1 {
			suffix := fmt.Sprintf("-%d", i)
			candidate = trimUsername(truncateRunes(base, maxUsernameLength-len(suffix))) + suffix
		}

		var count int64
		err := tx.
			WithContext(ctx).
			Model(&model.User{}).
			Where("LOWER(username) = LOWER(?)", candidate).
			Count(&count).
			Error
		if err != nil {
			return "", err
		}
		if count == 0 {
			return candidate, nil
		}
	}

	// Fall back to a random suffix for very common usernames
	suffix, err := utils.GenerateRandomAlphanumericString(8)
	if err != nil {
		return "", err
	}

	return trimUsername(truncateRunes(base, maxUsernameLength-len(suffix)-1)) + "-" + suffix, nil
}
