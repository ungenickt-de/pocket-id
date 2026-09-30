package identityprovider

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ory/fosite"
	"gorm.io/gorm"

	"github.com/pocket-id/pocket-id/backend/internal/apperror"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
)

const defaultScopes = "openid profile email"

// Service manages identity providers, the sign-in flow with them, and the links between external accounts and users
type Service struct {
	db          *gorm.DB
	rp          *relyingParty
	states      *stateCodec
	signer      TokenService
	auditLog    AuditLogger
	userCreator UserCreator
	scimSync    ScimSyncScheduler
	callbackURL string
}

func newService(deps Dependencies) (*Service, error) {
	states, err := newStateCodec(deps.EncryptionKey)
	if err != nil {
		return nil, err
	}

	return &Service{
		db:          deps.DB,
		rp:          newRelyingParty(deps.HTTPClient),
		states:      states,
		signer:      deps.Signer,
		auditLog:    deps.AuditLog,
		userCreator: deps.UserCreator,
		scimSync:    deps.ScimSync,
		callbackURL: strings.TrimRight(deps.AppURL, "/") + callbackPath,
	}, nil
}

// normalizeScopes turns the space-separated scope list into its canonical form and makes sure "openid" is requested
func normalizeScopes(scopes string) (string, error) {
	fields := strings.Fields(scopes)
	if len(fields) == 0 {
		return defaultScopes, nil
	}

	normalized := make([]string, 0, len(fields)+1)
	for _, scope := range fields {
		if !fosite.IsValidScopeToken(scope) {
			return "", apperror.InvalidField("scopes", "invalid_value", "contains an invalid scope")
		}
		if !slices.Contains(normalized, scope) {
			normalized = append(normalized, scope)
		}
	}

	// Without the "openid" scope the provider would not return an ID token
	if !slices.Contains(normalized, "openid") {
		normalized = append([]string{"openid"}, normalized...)
	}

	return strings.Join(normalized, " "), nil
}

func (s *Service) List(ctx context.Context, search string, listRequestOptions utils.ListRequestOptions) ([]IdentityProvider, utils.PaginationResponse, error) {
	query := s.db.
		WithContext(ctx).
		Model(&IdentityProvider{})

	if search != "" {
		like := "%" + search + "%"
		query = query.Where("name LIKE ? OR issuer LIKE ?", like, like)
	}

	var providers []IdentityProvider
	response, err := utils.PaginateFilterAndSort(listRequestOptions, query, &providers)
	return providers, response, err
}

// ListEnabled returns the providers users can sign in with, ordered by name
func (s *Service) ListEnabled(ctx context.Context) ([]IdentityProvider, error) {
	var providers []IdentityProvider
	err := s.db.
		WithContext(ctx).
		Where("enabled = ?", true).
		Order("name ASC").
		Find(&providers).
		Error
	if err != nil {
		return nil, err
	}

	return providers, nil
}

func (s *Service) Get(ctx context.Context, id string) (IdentityProvider, error) {
	var provider IdentityProvider
	err := s.db.
		WithContext(ctx).
		Where("id = ?", id).
		First(&provider).
		Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return IdentityProvider{}, apperror.NotFound("Identity provider")
	} else if err != nil {
		return IdentityProvider{}, err
	}

	return provider, nil
}

// getEnabled loads a provider for a sign-in, treating disabled providers as missing
func (s *Service) getEnabled(ctx context.Context, id string) (IdentityProvider, error) {
	provider, err := s.Get(ctx, id)
	if apperror.IsCode(err, apperror.CodeNotFound) || (err == nil && !provider.Enabled) {
		return IdentityProvider{}, apperror.IdentityProviderUnavailable()
	}

	return provider, err
}

func (s *Service) Create(ctx context.Context, input identityProviderInputDto) (IdentityProvider, error) {
	provider := IdentityProvider{}
	err := s.applyInput(ctx, &provider, input)
	if err != nil {
		return IdentityProvider{}, err
	}

	err = s.db.WithContext(ctx).Create(&provider).Error
	if err != nil {
		return IdentityProvider{}, err
	}

	return provider, nil
}

func (s *Service) Update(ctx context.Context, id string, input identityProviderInputDto) (IdentityProvider, error) {
	provider, err := s.Get(ctx, id)
	if err != nil {
		return IdentityProvider{}, err
	}

	err = s.applyInput(ctx, &provider, input)
	if err != nil {
		return IdentityProvider{}, err
	}
	provider.UpdatedAt = new(datatype.DateTime(time.Now()))

	err = s.db.WithContext(ctx).Save(&provider).Error
	if err != nil {
		return IdentityProvider{}, err
	}

	return provider, nil
}

// applyInput validates the input and copies it onto the provider
func (s *Service) applyInput(ctx context.Context, provider *IdentityProvider, input identityProviderInputDto) error {
	scopes, err := normalizeScopes(input.Scopes)
	if err != nil {
		return err
	}

	// Load the discovery document of enabled providers right away, so a mistyped issuer is reported to the admin instead of breaking the sign-in page
	issuer := strings.TrimSpace(input.Issuer)
	if input.Enabled {
		_, err = s.rp.Discover(ctx, issuer)
		if err != nil {
			return apperror.IdentityProviderDiscoveryFailed(err)
		}
	}

	provider.Name = strings.TrimSpace(input.Name)
	provider.Enabled = input.Enabled
	provider.Issuer = issuer
	provider.ClientID = strings.TrimSpace(input.ClientID)
	provider.Scopes = scopes
	provider.AutoCreateUsers = input.AutoCreateUsers
	provider.AutoLinkUsers = input.AutoLinkUsers
	provider.AutoUpdateUsers = input.AutoUpdateUsers

	// A missing secret keeps the stored one, so the admin does not have to enter it again on every change
	if input.ClientSecret != nil {
		provider.ClientSecret = datatype.EncryptedString(strings.TrimSpace(*input.ClientSecret))
	}

	return nil
}

// Delete removes a provider, which also removes all links to it
func (s *Service) Delete(ctx context.Context, id string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// The links are deleted explicitly, since SQLite only cascades when foreign keys are enforced on the connection
		err := tx.
			WithContext(ctx).
			Where("identity_provider_id = ?", id).
			Delete(&Link{}).
			Error
		if err != nil {
			return fmt.Errorf("failed to delete links: %w", err)
		}

		result := tx.
			WithContext(ctx).
			Where("id = ?", id).
			Delete(&IdentityProvider{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return apperror.NotFound("Identity provider")
		}

		return nil
	})
}

// ListLinks returns the external accounts linked to a user
func (s *Service) ListLinks(ctx context.Context, userID string) ([]Link, error) {
	var links []Link
	err := s.db.
		WithContext(ctx).
		Preload("IdentityProvider").
		Where("user_id = ?", userID).
		Order("created_at ASC").
		Find(&links).
		Error
	if err != nil {
		return nil, err
	}

	return links, nil
}

// DeleteLink removes the link between a user and an external account
func (s *Service) DeleteLink(ctx context.Context, userID, linkID, ipAddress, userAgent string) error {
	tx := s.db.Begin()
	defer func() {
		tx.Rollback()
	}()

	var link Link
	err := tx.
		WithContext(ctx).
		Preload("IdentityProvider").
		Where("id = ? AND user_id = ?", linkID, userID).
		First(&link).
		Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return apperror.NotFound("Linked account")
	} else if err != nil {
		return err
	}

	err = tx.WithContext(ctx).Delete(&link).Error
	if err != nil {
		return err
	}

	s.auditLog.Create(ctx, model.AuditLogEventIdentityProviderUnlinked, ipAddress, userAgent, userID, model.AuditLogData{
		"identityProvider": link.IdentityProvider.Name,
	}, tx)

	return tx.Commit().Error
}
