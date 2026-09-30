package identityprovider

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pocket-id/pocket-id/backend/internal/apperror"
	"github.com/pocket-id/pocket-id/backend/internal/model"
)

func TestLoginWithoutLinkedAccount(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, nil)

	// Without auto creation or linking an unknown external account is rejected
	result, err := env.login(t, provider.ID, fakeAccount{Subject: "alice", Claims: map[string]any{"email": "alice@example.com", "email_verified": true}})
	require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderAccountNotLinked), "unexpected error: %v", err)
	assert.Equal(t, flowModeLogin, result.Mode)
	assert.Equal(t, "/settings/apps", result.Redirect)
	assert.Equal(t, int64(0), countRows(t, env.db, &model.User{}))
}

func TestLoginCreatesUser(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, func(input *identityProviderInputDto) {
		input.AutoCreateUsers = true
	})

	// The ID token only carries the subject, the profile comes from the userinfo endpoint like with Zitadel's defaults
	account := fakeAccount{
		Subject: "alice-sub",
		Userinfo: map[string]any{
			"email":              "alice@example.com",
			"email_verified":     true,
			"preferred_username": "alice",
			"given_name":         "Alice",
			"family_name":        "Liddell",
			"name":               "Alice Liddell",
		},
	}

	// The first sign-in creates and links the user
	result, err := env.login(t, provider.ID, account)
	require.NoError(t, err)
	assert.Equal(t, "/settings/apps", result.Redirect)
	assert.Equal(t, "alice", result.User.Username)
	require.NotNil(t, result.User.Email)
	assert.Equal(t, "alice@example.com", *result.User.Email)
	assert.True(t, result.User.EmailVerified)
	assert.Equal(t, "Alice", result.User.FirstName)
	assert.Equal(t, "Liddell", result.User.LastName)
	assert.Equal(t, "Alice Liddell", result.User.DisplayName)
	assert.Equal(t, "session-"+result.User.ID+"-fed", result.AccessToken)
	assert.Equal(t, []model.AuditLogEvent{
		model.AuditLogEventAccountCreated,
		model.AuditLogEventIdentityProviderLinked,
		model.AuditLogEventIdentityProviderSignIn,
	}, env.auditLog.recorded())

	// Signing in again reuses the linked user
	second, err := env.login(t, provider.ID, account)
	require.NoError(t, err)
	assert.Equal(t, result.User.ID, second.User.ID)
	assert.Equal(t, int64(1), countRows(t, env.db, &model.User{}))
	assert.Equal(t, int64(1), countRows(t, env.db, &Link{}))
}

func TestLoginCreatesUserWithUniqueUsername(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, func(input *identityProviderInputDto) {
		input.AutoCreateUsers = true
	})
	env.createUser(t, "bob", "bob@local.example")

	// The preferred username is taken, so a suffix is added
	result, err := env.login(t, provider.ID, fakeAccount{Subject: "bob-sub", Claims: map[string]any{
		"email":              "bob@external.example",
		"preferred_username": "bob",
	}})
	require.NoError(t, err)
	assert.Equal(t, "bob-2", result.User.Username)
	assert.False(t, result.User.EmailVerified)
}

func TestLoginDoesNotCreateUserForExistingEmail(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, func(input *identityProviderInputDto) {
		input.AutoCreateUsers = true
	})
	env.createUser(t, "carol", "carol@example.com")

	// Taking over an existing account requires linking, not creating a duplicate
	_, err := env.login(t, provider.ID, fakeAccount{Subject: "carol-sub", Claims: map[string]any{"email": "Carol@example.com"}})
	require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderEmailInUse), "unexpected error: %v", err)
}

func TestLoginRequiresEmailWhenConfigured(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, func(input *identityProviderInputDto) {
		input.AutoCreateUsers = true
	})

	_, err := env.login(t, provider.ID, fakeAccount{Subject: "no-email"})
	require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderEmailRequired), "unexpected error: %v", err)
}

func TestLoginLinksUserByVerifiedEmail(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, func(input *identityProviderInputDto) {
		input.AutoLinkUsers = true
	})
	user := env.createUser(t, "dave", "dave@example.com")

	// An unverified email address is not trusted for linking
	_, err := env.login(t, provider.ID, fakeAccount{Subject: "dave-sub", Claims: map[string]any{"email": "dave@example.com", "email_verified": false}})
	require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderAccountNotLinked), "unexpected error: %v", err)

	// A verified address links the account, even when the provider sends the flag as a string
	result, err := env.login(t, provider.ID, fakeAccount{Subject: "dave-sub", Claims: map[string]any{"email": "DAVE@example.com", "email_verified": "true"}})
	require.NoError(t, err)
	assert.Equal(t, user.ID, result.User.ID)

	links, err := env.service.ListLinks(t.Context(), user.ID)
	require.NoError(t, err)
	require.Len(t, links, 1)
	assert.Equal(t, "dave-sub", links[0].Subject)
	assert.Equal(t, provider.Name, links[0].IdentityProvider.Name)
}

func TestLoginUpdatesProfile(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, func(input *identityProviderInputDto) {
		input.AutoCreateUsers = true
		input.AutoUpdateUsers = true
	})

	account := fakeAccount{Subject: "erin-sub", Claims: map[string]any{
		"email":       "erin@example.com",
		"given_name":  "Erin",
		"family_name": "Old",
	}}
	created, err := env.login(t, provider.ID, account)
	require.NoError(t, err)

	// A changed profile at the provider is copied on the next sign-in, while missing claims keep the stored values
	account.Claims = map[string]any{
		"email":          "erin.new@example.com",
		"email_verified": true,
		"family_name":    "New",
	}
	updated, err := env.login(t, provider.ID, account)
	require.NoError(t, err)
	assert.Equal(t, created.User.ID, updated.User.ID)
	assert.Equal(t, "Erin", updated.User.FirstName)
	assert.Equal(t, "New", updated.User.LastName)
	require.NotNil(t, updated.User.Email)
	assert.Equal(t, "erin.new@example.com", *updated.User.Email)
	assert.True(t, updated.User.EmailVerified)

	var stored model.User
	require.NoError(t, env.db.First(&stored, "id = ?", created.User.ID).Error)
	assert.Equal(t, "New", stored.LastName)
	assert.Equal(t, "erin.new@example.com", *stored.Email)
}

func TestLoginRejectsDisabledUser(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, func(input *identityProviderInputDto) {
		input.AutoCreateUsers = true
	})

	account := fakeAccount{Subject: "frank-sub", Claims: map[string]any{"email": "frank@example.com"}}
	result, err := env.login(t, provider.ID, account)
	require.NoError(t, err)
	require.NoError(t, env.db.Model(&model.User{}).Where("id = ?", result.User.ID).Update("disabled", true).Error)

	_, err = env.login(t, provider.ID, account)
	require.True(t, apperror.IsCode(err, apperror.CodeUserDisabled), "unexpected error: %v", err)
}

func TestLoginRejectsDisabledProvider(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, nil)
	provider.Enabled = false
	require.NoError(t, env.db.Save(&provider).Error)

	_, _, err := env.service.StartLogin(t.Context(), provider.ID, "/")
	require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderUnavailable), "unexpected error: %v", err)

	enabled, err := env.service.ListEnabled(t.Context())
	require.NoError(t, err)
	assert.Empty(t, enabled)
}

func TestCallbackValidation(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, func(input *identityProviderInputDto) {
		input.AutoCreateUsers = true
	})
	account := fakeAccount{Subject: "grace-sub", Claims: map[string]any{"email": "grace@example.com"}}

	start := func(t *testing.T) (code, state, stateCookie string) {
		t.Helper()
		authURL, stateCookie, err := env.service.StartLogin(t.Context(), provider.ID, "/interaction?interaction=abc")
		require.NoError(t, err)
		code, state = env.provider.authorize(t, authURL, account)
		return code, state, stateCookie
	}

	t.Run("state from another browser is rejected", func(t *testing.T) {
		code, _, _ := start(t)
		_, _, otherCookie := start(t)
		_, err := env.service.HandleCallback(t.Context(), env.config, callbackInput{State: "forged", Code: code, StateCookie: otherCookie})
		require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderStateInvalid), "unexpected error: %v", err)
	})

	t.Run("missing state cookie is rejected", func(t *testing.T) {
		code, state, _ := start(t)
		result, err := env.service.HandleCallback(t.Context(), env.config, callbackInput{State: state, Code: code})
		require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderStateInvalid), "unexpected error: %v", err)
		assert.Equal(t, defaultRedirect, result.Redirect)
	})

	t.Run("error from the provider is reported", func(t *testing.T) {
		_, state, stateCookie := start(t)
		result, err := env.service.HandleCallback(t.Context(), env.config, callbackInput{State: state, Error: "access_denied", StateCookie: stateCookie})
		require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderError), "unexpected error: %v", err)
		assert.Equal(t, "/interaction?interaction=abc", result.Redirect)
	})

	t.Run("mismatching issuer in the authorization response is rejected", func(t *testing.T) {
		code, state, stateCookie := start(t)
		_, err := env.service.HandleCallback(t.Context(), env.config, callbackInput{State: state, Code: code, Issuer: "https://attacker.example", StateCookie: stateCookie})
		require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderLoginFailed), "unexpected error: %v", err)
	})

	t.Run("ID token with a different nonce is rejected", func(t *testing.T) {
		env.provider.mutateIDToken = func(b *jwt.Builder) *jwt.Builder { return b.Claim("nonce", "replayed") }
		defer func() { env.provider.mutateIDToken = nil }()

		code, state, stateCookie := start(t)
		_, err := env.service.HandleCallback(t.Context(), env.config, callbackInput{State: state, Code: code, StateCookie: stateCookie})
		require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderLoginFailed), "unexpected error: %v", err)
	})

	t.Run("ID token for another client is rejected", func(t *testing.T) {
		env.provider.mutateIDToken = func(b *jwt.Builder) *jwt.Builder { return b.Audience([]string{"someone-else"}) }
		defer func() { env.provider.mutateIDToken = nil }()

		code, state, stateCookie := start(t)
		_, err := env.service.HandleCallback(t.Context(), env.config, callbackInput{State: state, Code: code, StateCookie: stateCookie})
		require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderLoginFailed), "unexpected error: %v", err)
	})

	t.Run("expired ID token is rejected", func(t *testing.T) {
		env.provider.mutateIDToken = func(b *jwt.Builder) *jwt.Builder { return b.Expiration(time.Now().Add(-time.Hour)) }
		defer func() { env.provider.mutateIDToken = nil }()

		code, state, stateCookie := start(t)
		_, err := env.service.HandleCallback(t.Context(), env.config, callbackInput{State: state, Code: code, StateCookie: stateCookie})
		require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderLoginFailed), "unexpected error: %v", err)
	})

	t.Run("valid callback signs in", func(t *testing.T) {
		code, state, stateCookie := start(t)
		result, err := env.service.HandleCallback(t.Context(), env.config, callbackInput{State: state, Code: code, StateCookie: stateCookie})
		require.NoError(t, err)
		assert.Equal(t, "/interaction?interaction=abc", result.Redirect)
		assert.NotEmpty(t, result.AccessToken)
	})
}

func TestLinkAccount(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, nil)
	heidi := env.createUser(t, "heidi", "heidi@example.com")
	ivan := env.createUser(t, "ivan", "ivan@example.com")
	account := fakeAccount{Subject: "heidi-external", Claims: map[string]any{"email": "heidi@external.example"}}

	// The session must still belong to the user who started linking
	_, err := env.link(t, provider.ID, heidi.ID, ivan.ID, account)
	require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderSessionChanged), "unexpected error: %v", err)
	_, err = env.link(t, provider.ID, heidi.ID, "", account)
	require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderSessionChanged), "unexpected error: %v", err)

	// Linking succeeds and returns to the account settings
	result, err := env.link(t, provider.ID, heidi.ID, heidi.ID, account)
	require.NoError(t, err)
	assert.Equal(t, flowModeLink, result.Mode)
	assert.Equal(t, accountSettingsPath, result.Redirect)
	assert.Empty(t, result.AccessToken)

	// Linking the same external account again is harmless
	_, err = env.link(t, provider.ID, heidi.ID, heidi.ID, account)
	require.NoError(t, err)

	// Another user cannot take over the external account
	_, err = env.link(t, provider.ID, ivan.ID, ivan.ID, account)
	require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderAlreadyLinked), "unexpected error: %v", err)

	// A user can be linked to only one account per provider
	_, err = env.link(t, provider.ID, heidi.ID, heidi.ID, fakeAccount{Subject: "heidi-second"})
	require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderUserAlreadyLinked), "unexpected error: %v", err)

	// The linked account can now be used to sign in
	login, err := env.login(t, provider.ID, account)
	require.NoError(t, err)
	assert.Equal(t, heidi.ID, login.User.ID)

	// Unlinking is scoped to the owner of the link
	links, err := env.service.ListLinks(t.Context(), heidi.ID)
	require.NoError(t, err)
	require.Len(t, links, 1)
	require.NotNil(t, links[0].Email)
	assert.Equal(t, "heidi@external.example", *links[0].Email)
	assert.NotNil(t, links[0].LastUsedAt)

	err = env.service.DeleteLink(t.Context(), ivan.ID, links[0].ID, "", "")
	require.True(t, apperror.IsCode(err, apperror.CodeNotFound), "unexpected error: %v", err)
	require.NoError(t, env.service.DeleteLink(t.Context(), heidi.ID, links[0].ID, "", ""))

	_, err = env.login(t, provider.ID, account)
	require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderAccountNotLinked), "unexpected error: %v", err)
}

func TestDeleteProviderRemovesLinks(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, func(input *identityProviderInputDto) {
		input.AutoCreateUsers = true
	})

	_, err := env.login(t, provider.ID, fakeAccount{Subject: "judy-sub", Claims: map[string]any{"email": "judy@example.com"}})
	require.NoError(t, err)
	require.Equal(t, int64(1), countRows(t, env.db, &Link{}))

	require.NoError(t, env.service.Delete(t.Context(), provider.ID))
	assert.Equal(t, int64(0), countRows(t, env.db, &Link{}))
	assert.Equal(t, int64(1), countRows(t, env.db, &model.User{}))

	err = env.service.Delete(t.Context(), provider.ID)
	require.True(t, apperror.IsCode(err, apperror.CodeNotFound), "unexpected error: %v", err)
}
