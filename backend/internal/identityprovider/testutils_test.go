package identityprovider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pocket-id/pocket-id/backend/internal/appconfig"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	"github.com/pocket-id/pocket-id/backend/internal/service"
	jwkutils "github.com/pocket-id/pocket-id/backend/internal/utils/jwk"
	testutils "github.com/pocket-id/pocket-id/backend/internal/utils/testing"
)

const (
	testClientID     = "pocket-id"
	testClientSecret = "top-secret"
	testAppURL       = "https://pocket-id.example.com"
)

// fakeAccount is the account the fake provider signs in with when it issues the next authorization code
type fakeAccount struct {
	Subject string
	Claims  map[string]any
	// Userinfo is returned by the userinfo endpoint, defaulting to no additional claims
	Userinfo map[string]any
}

// pendingCode is an authorization code the fake provider issued, along with what the token request must prove
type pendingCode struct {
	account       fakeAccount
	nonce         string
	codeChallenge string
	redirectURI   string
}

// fakeProvider is a minimal OpenID Provider serving discovery, JWKS, token and userinfo endpoints
type fakeProvider struct {
	t      *testing.T
	server *httptest.Server
	key    jwk.Key
	alg    jwa.KeyAlgorithm

	lock  sync.Mutex
	codes map[string]pendingCode
	// accessTokens maps issued access tokens to the account they belong to
	accessTokens map[string]fakeAccount
	// mutateIDToken lets tests tamper with the next ID token
	mutateIDToken func(b *jwt.Builder) *jwt.Builder
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()

	key, err := jwkutils.GenerateKey(jwa.RS256().String(), "")
	require.NoError(t, err)
	alg, ok := key.Algorithm()
	require.True(t, ok)

	p := &fakeProvider{
		t:            t,
		key:          key,
		alg:          alg,
		codes:        make(map[string]pendingCode),
		accessTokens: make(map[string]fakeAccount),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)

	return p
}

func (p *fakeProvider) issuer() string {
	return p.server.URL
}

func (p *fakeProvider) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(body)
	if err != nil {
		p.t.Errorf("failed to encode response: %v", err)
	}
}

func (p *fakeProvider) discovery(w http.ResponseWriter, _ *http.Request) {
	p.writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.issuer(),
		"authorization_endpoint":                p.issuer() + "/authorize",
		"token_endpoint":                        p.issuer() + "/token",
		"userinfo_endpoint":                     p.issuer() + "/userinfo",
		"jwks_uri":                              p.issuer() + "/jwks",
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
	})
}

func (p *fakeProvider) jwks(w http.ResponseWriter, _ *http.Request) {
	publicKey, err := p.key.PublicKey()
	if err == nil {
		set := jwk.NewSet()
		err = set.AddKey(publicKey)
		if err == nil {
			p.writeJSON(w, http.StatusOK, set)
			return
		}
	}

	p.t.Errorf("failed to build key set: %v", err)
	w.WriteHeader(http.StatusInternalServerError)
}

// authorize simulates the user signing in at the provider and returns the code the browser would bring back
func (p *fakeProvider) authorize(t *testing.T, authURL string, account fakeAccount) (code, state string) {
	t.Helper()

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)
	query := parsed.Query()
	require.Equal(t, p.issuer()+"/authorize", parsed.Scheme+"://"+parsed.Host+parsed.Path)
	require.Equal(t, "code", query.Get("response_type"))
	require.Equal(t, testClientID, query.Get("client_id"))
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.NotEmpty(t, query.Get("nonce"))
	require.NotEmpty(t, query.Get("state"))

	code = "code-" + account.Subject + "-" + query.Get("state")[:8]
	p.lock.Lock()
	p.codes[code] = pendingCode{
		account:       account,
		nonce:         query.Get("nonce"),
		codeChallenge: query.Get("code_challenge"),
		redirectURI:   query.Get("redirect_uri"),
	}
	p.lock.Unlock()

	return code, query.Get("state")
}

func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	// Authenticate the client with client_secret_basic
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok || clientID != testClientID || clientSecret != testClientSecret {
		p.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	// Redeem the code exactly once and check the PKCE verifier and redirect URI
	p.lock.Lock()
	pending, found := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	mutate := p.mutateIDToken
	p.lock.Unlock()

	verifierHash := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found ||
		r.PostForm.Get("grant_type") != "authorization_code" ||
		base64.RawURLEncoding.EncodeToString(verifierHash[:]) != pending.codeChallenge ||
		r.PostForm.Get("redirect_uri") != pending.redirectURI {
		p.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	// Issue the ID token with the account's claims
	builder := jwt.NewBuilder().
		Issuer(p.issuer()).
		Subject(pending.account.Subject).
		Audience([]string{testClientID}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5*time.Minute)).
		Claim("nonce", pending.nonce)
	for key, value := range pending.account.Claims {
		builder = builder.Claim(key, value)
	}
	if mutate != nil {
		builder = mutate(builder)
	}
	idToken, err := builder.Build()
	if err != nil {
		p.t.Errorf("failed to build ID token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	signed, err := jwt.Sign(idToken, jwt.WithKey(p.alg, p.key))
	if err != nil {
		p.t.Errorf("failed to sign ID token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	accessToken := "access-" + pending.account.Subject
	p.lock.Lock()
	p.accessTokens[accessToken] = pending.account
	p.lock.Unlock()

	p.writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     string(signed),
	})
}

func (p *fakeProvider) userinfo(w http.ResponseWriter, r *http.Request) {
	accessToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	p.lock.Lock()
	account, found := p.accessTokens[accessToken]
	p.lock.Unlock()
	if !found {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims := map[string]any{"sub": account.Subject}
	for key, value := range account.Userinfo {
		claims[key] = value
	}
	p.writeJSON(w, http.StatusOK, claims)
}

// staticAppConfig serves a fixed configuration, since the real service needs the actor host
type staticAppConfig struct {
	config *appconfig.AppConfigModel
}

func (s staticAppConfig) GetConfig(_ context.Context) (*appconfig.AppConfigModel, error) {
	return s.config, nil
}

type fakeSigner struct{}

func (fakeSigner) GenerateAccessToken(user model.User, authenticationMethod string, _ time.Duration) (string, error) {
	return "session-" + user.ID + "-" + authenticationMethod, nil
}

// fakeAuditLogger records the events so tests can assert on them
type fakeAuditLogger struct {
	lock   sync.Mutex
	events []model.AuditLogEvent
	data   []model.AuditLogData
}

func (f *fakeAuditLogger) Create(_ context.Context, event model.AuditLogEvent, _, _, _ string, data model.AuditLogData, _ *gorm.DB) (model.AuditLog, bool) {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.events = append(f.events, event)
	f.data = append(f.data, data)
	return model.AuditLog{}, true
}

func (f *fakeAuditLogger) CreateSignInEventWithEmail(ctx context.Context, event model.AuditLogEvent, data model.AuditLogData, ipAddress, userAgent, userID string, tx *gorm.DB, _ bool) model.AuditLog {
	log, _ := f.Create(ctx, event, ipAddress, userAgent, userID, data, tx)
	return log
}

func (f *fakeAuditLogger) recorded() []model.AuditLogEvent {
	f.lock.Lock()
	defer f.lock.Unlock()
	return append([]model.AuditLogEvent(nil), f.events...)
}

type testEnv struct {
	db       *gorm.DB
	provider *fakeProvider
	service  *Service
	module   *Module
	auditLog *fakeAuditLogger
	config   *appconfig.AppConfigModel
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	db := testutils.NewDatabaseForTest(t)
	// Deleting providers and users relies on the ON DELETE CASCADE that production enforces
	require.NoError(t, db.Exec("PRAGMA foreign_keys = ON").Error)

	provider := newFakeProvider(t)
	auditLog := &fakeAuditLogger{}
	config := appconfig.NewTestConfig(nil)

	module, err := New(Dependencies{
		DB:            db,
		HTTPClient:    provider.server.Client(),
		AppURL:        testAppURL,
		EncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		Signer:        fakeSigner{},
		AuditLog:      auditLog,
		UserCreator:   service.NewUserService(db, nil, nil, nil, nil, nil, nil, nil),
		AppConfig:     staticAppConfig{config: config},
	})
	require.NoError(t, err)

	return &testEnv{
		db:       db,
		provider: provider,
		service:  module.service,
		module:   module,
		auditLog: auditLog,
		config:   config,
	}
}

// createProvider stores an enabled identity provider pointing at the fake provider
func (e *testEnv) createProvider(t *testing.T, mutate func(input *identityProviderInputDto)) IdentityProvider {
	t.Helper()

	secret := testClientSecret
	input := identityProviderInputDto{
		Name:         "Fake IdP",
		Enabled:      true,
		Issuer:       e.provider.issuer(),
		ClientID:     testClientID,
		ClientSecret: &secret,
	}
	if mutate != nil {
		mutate(&input)
	}

	provider, err := e.service.Create(t.Context(), input)
	require.NoError(t, err)
	return provider
}

// createUser stores a local user
func (e *testEnv) createUser(t *testing.T, username, email string) model.User {
	t.Helper()

	user := model.User{Username: username, Email: &email, FirstName: username}
	require.NoError(t, e.db.Create(&user).Error)
	return user
}

// login runs a complete sign-in for the account and returns the result of the callback
func (e *testEnv) login(t *testing.T, providerID string, account fakeAccount) (callbackResult, error) {
	t.Helper()

	authURL, stateCookie, err := e.service.StartLogin(t.Context(), providerID, "/settings/apps")
	require.NoError(t, err)
	code, state := e.provider.authorize(t, authURL, account)

	return e.service.HandleCallback(t.Context(), e.config, callbackInput{
		State:       state,
		Code:        code,
		StateCookie: stateCookie,
		IPAddress:   "127.0.0.1",
		UserAgent:   "test",
	})
}

// link runs a complete link flow for the account on behalf of the signed-in user
func (e *testEnv) link(t *testing.T, providerID, userID, signedInUserID string, account fakeAccount) (callbackResult, error) {
	t.Helper()

	authURL, stateCookie, err := e.service.StartLink(t.Context(), providerID, userID)
	require.NoError(t, err)
	code, state := e.provider.authorize(t, authURL, account)

	return e.service.HandleCallback(t.Context(), e.config, callbackInput{
		State:          state,
		Code:           code,
		StateCookie:    stateCookie,
		SignedInUserID: signedInUserID,
		IPAddress:      "127.0.0.1",
		UserAgent:      "test",
	})
}

func countRows(t *testing.T, db *gorm.DB, value any) int64 {
	t.Helper()

	var count int64
	require.NoError(t, db.Model(value).Count(&count).Error)
	return count
}
