package identityprovider

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pocket-id/pocket-id/backend/internal/apperror"
)

func TestProviderCrud(t *testing.T) {
	env := newTestEnv(t)

	// Scopes are normalized and always include "openid"
	provider := env.createProvider(t, func(input *identityProviderInputDto) {
		input.Scopes = "email  profile email"
	})
	assert.Equal(t, "openid email profile", provider.Scopes)
	assert.Equal(t, testClientSecret, provider.ClientSecret.String())

	// Updating without a client secret keeps the stored one
	updated, err := env.service.Update(t.Context(), provider.ID, identityProviderInputDto{
		Name:     "Renamed",
		Enabled:  true,
		Issuer:   env.provider.issuer(),
		ClientID: testClientID,
	})
	require.NoError(t, err)
	assert.Equal(t, "Renamed", updated.Name)
	assert.Equal(t, defaultScopes, updated.Scopes)

	loaded, err := env.service.Get(t.Context(), provider.ID)
	require.NoError(t, err)
	assert.Equal(t, testClientSecret, loaded.ClientSecret.String())
	assert.True(t, newIdentityProviderDto(loaded).HasClientSecret)

	// An empty client secret turns the provider into a public client
	empty := ""
	updated, err = env.service.Update(t.Context(), provider.ID, identityProviderInputDto{
		Name:         "Renamed",
		Enabled:      true,
		Issuer:       env.provider.issuer(),
		ClientID:     testClientID,
		ClientSecret: &empty,
	})
	require.NoError(t, err)
	assert.False(t, newIdentityProviderDto(updated).HasClientSecret)
}

func TestProviderValidation(t *testing.T) {
	env := newTestEnv(t)

	// An enabled provider must be reachable
	_, err := env.service.Create(t.Context(), identityProviderInputDto{
		Name:     "Broken",
		Enabled:  true,
		Issuer:   env.provider.issuer() + "/does-not-exist",
		ClientID: testClientID,
	})
	require.True(t, apperror.IsCode(err, apperror.CodeIdentityProviderDiscoveryFailed), "unexpected error: %v", err)

	// A disabled provider can be prepared before the identity provider is reachable
	_, err = env.service.Create(t.Context(), identityProviderInputDto{
		Name:     "Prepared",
		Issuer:   "https://idp.invalid",
		ClientID: testClientID,
	})
	require.NoError(t, err)

	// Invalid scopes are rejected
	_, err = env.service.Create(t.Context(), identityProviderInputDto{
		Name:     "Scopes",
		Issuer:   "https://idp.invalid",
		ClientID: testClientID,
		Scopes:   `openid "quoted"`,
	})
	require.True(t, apperror.IsCode(err, apperror.CodeValidationFailed), "unexpected error: %v", err)
}

func TestStateCodec(t *testing.T) {
	codec, err := newStateCodec([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)

	state := loginState{
		ProviderID:   "provider",
		State:        "state-value",
		Nonce:        "nonce",
		CodeVerifier: "verifier",
		Redirect:     "/settings",
		Mode:         flowModeLogin,
		ExpiresAt:    time.Now().Add(time.Minute),
	}
	encoded, err := codec.Encode(state)
	require.NoError(t, err)

	t.Run("round trip", func(t *testing.T) {
		decoded, err := codec.Decode(encoded, "state-value")
		require.NoError(t, err)
		assert.Equal(t, state.ProviderID, decoded.ProviderID)
		assert.Equal(t, state.CodeVerifier, decoded.CodeVerifier)
	})

	t.Run("wrong state parameter", func(t *testing.T) {
		_, err := codec.Decode(encoded, "other-state")
		require.Error(t, err)
	})

	t.Run("tampered cookie", func(t *testing.T) {
		tampered := []byte(encoded)
		tampered[len(tampered)/2] ^= 1
		_, err := codec.Decode(string(tampered), "state-value")
		require.Error(t, err)
	})

	t.Run("cookie from another key", func(t *testing.T) {
		other, err := newStateCodec([]byte("another-master-key-for-the-tests!"))
		require.NoError(t, err)
		_, err = other.Decode(encoded, "state-value")
		require.Error(t, err)
	})

	t.Run("expired state", func(t *testing.T) {
		expiredCodec := &stateCodec{key: codec.key, now: func() time.Time { return time.Now().Add(time.Hour) }}
		_, err := expiredCodec.Decode(encoded, "state-value")
		require.Error(t, err)
	})
}

func TestSanitizeRedirect(t *testing.T) {
	tests := map[string]string{
		"/settings/apps":                 "/settings/apps",
		"/interaction?interaction=abc":   "/interaction?interaction=abc",
		"":                               defaultRedirect,
		"settings":                       defaultRedirect,
		"https://evil.example":           defaultRedirect,
		"//evil.example":                 defaultRedirect,
		"/\\evil.example":                defaultRedirect,
		"/\t/evil.example":               defaultRedirect,
		"/\n/evil.example":               defaultRedirect,
		"javascript:alert(1)":            defaultRedirect,
		"/login?redirect=%2Fsettings%2F": "/login?redirect=%2Fsettings%2F",
	}

	for input, expected := range tests {
		assert.Equal(t, expected, sanitizeRedirect(input), "input %q", input)
	}
}

func TestSanitizeErrorCode(t *testing.T) {
	assert.Equal(t, "access_denied", sanitizeErrorCode("access_denied"))
	assert.Equal(t, "scriptalert1script", sanitizeErrorCode("<script>alert(1)</script>"))
	assert.Equal(t, "unknown_error", sanitizeErrorCode("!!!"))
}

func TestExternalIdentity(t *testing.T) {
	t.Run("userinfo of another subject is rejected", func(t *testing.T) {
		_, err := newExternalIdentity(map[string]any{"sub": "a"}, map[string]any{"sub": "b", "email": "b@example.com"})
		require.Error(t, err)
	})

	t.Run("invalid email is ignored", func(t *testing.T) {
		identity, err := newExternalIdentity(map[string]any{"sub": "a", "email": "Name <a@example.com>"}, nil)
		require.NoError(t, err)
		assert.Nil(t, identity.Email)
	})

	t.Run("username derivation", func(t *testing.T) {
		email := "max.mustermann@example.com"
		tests := []struct {
			identity externalIdentity
			expected string
		}{
			{externalIdentity{PreferredUsername: "max"}, "max"},
			{externalIdentity{PreferredUsername: "max@org.example"}, "max@org.example"},
			{externalIdentity{PreferredUsername: "Max Müller", Email: &email}, "Max.Mller"},
			{externalIdentity{PreferredUsername: "__", Email: &email}, "max.mustermann"},
			{externalIdentity{Name: "Erika Mustermann"}, "Erika.Mustermann"},
			{externalIdentity{PreferredUsername: "ÄÖÜ"}, fallbackUsername},
			{externalIdentity{}, fallbackUsername},
		}

		for _, test := range tests {
			assert.Equal(t, test.expected, test.identity.username(), "identity %+v", test.identity)
		}
	})

	t.Run("names are split from the full name", func(t *testing.T) {
		first, last, display := externalIdentity{Name: "Erika Maria Mustermann"}.names()
		assert.Equal(t, "Erika", first)
		assert.Equal(t, "Maria Mustermann", last)
		assert.Equal(t, "Erika Maria Mustermann", display)

		first, last, display = externalIdentity{GivenName: "Max", FamilyName: "Mustermann"}.names()
		assert.Equal(t, "Max", first)
		assert.Equal(t, "Mustermann", last)
		assert.Equal(t, "Max Mustermann", display)
	})
}
