package identityprovider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pocket-id/pocket-id/backend/internal/utils/cookie"
)

// newTestRouter mounts the module with stand-in middlewares, where the signed-in user is taken from the X-Test-User header
func newTestRouter(env *testEnv) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Surface handler errors as a failed response, which the error middleware does in production
	r.Use(func(c *gin.Context) {
		c.Next()
		if len(c.Errors) > 0 && !c.Writer.Written() {
			c.String(http.StatusInternalServerError, c.Errors.String())
		}
	})

	pass := func(c *gin.Context) { c.Next() }
	auth := func(c *gin.Context) {
		if userID := c.GetHeader("X-Test-User"); userID != "" {
			c.Set("userID", userID)
		}
		c.Next()
	}
	env.module.RegisterRoutes(r.Group("/api"), pass, auth, auth, pass)

	return r
}

func findCookie(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestHandlerSignInFlow(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, func(input *identityProviderInputDto) {
		input.AutoCreateUsers = true
	})
	router := newTestRouter(env)

	// The sign-in page lists the enabled provider
	res := httptest.NewRecorder()
	router.ServeHTTP(res, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/identity-providers/public", nil))
	require.Equal(t, http.StatusOK, res.Code)
	assert.JSONEq(t, `[{"id":"`+provider.ID+`","name":"Fake IdP"}]`, res.Body.String())

	// Starting the sign-in returns the authorization URL and stores the state in a cookie scoped to the callback
	res = httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/identity-providers/"+provider.ID+"/login", strings.NewReader(`{"redirect":"/settings/apps"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())

	var start startResponseDto
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &start))
	stateCookie := findCookie(res.Result(), cookie.IdentityProviderStateCookieName)
	require.NotNil(t, stateCookie)
	assert.Equal(t, callbackPath, stateCookie.Path)
	assert.True(t, stateCookie.HttpOnly)
	assert.Contains(t, start.URL, "redirect_uri="+url.QueryEscape(testAppURL+callbackPath))

	// The callback signs the user in and sends the browser to the original destination
	code, state := env.provider.authorize(t, start.URL, fakeAccount{Subject: "kim-sub", Claims: map[string]any{"email": "kim@example.com"}})
	res = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, callbackPath+"?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil)
	req.AddCookie(stateCookie)
	router.ServeHTTP(res, req)
	require.Equal(t, http.StatusFound, res.Code, res.Body.String())
	assert.Equal(t, "/settings/apps", res.Header().Get("Location"))

	accessTokenCookie := findCookie(res.Result(), cookie.AccessTokenCookieName)
	require.NotNil(t, accessTokenCookie)
	assert.NotEmpty(t, accessTokenCookie.Value)
	clearedStateCookie := findCookie(res.Result(), cookie.IdentityProviderStateCookieName)
	require.NotNil(t, clearedStateCookie)
	assert.Empty(t, clearedStateCookie.Value)

	// Replaying the callback without the consumed state cookie fails and returns to the sign-in page
	res = httptest.NewRecorder()
	router.ServeHTTP(res, httptest.NewRequestWithContext(t.Context(), http.MethodGet, callbackPath+"?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil))
	require.Equal(t, http.StatusFound, res.Code)
	assert.Equal(t, "/login?identityProviderError=identity_provider_state_invalid", res.Header().Get("Location"))
	assert.Nil(t, findCookie(res.Result(), cookie.AccessTokenCookieName))
}

func TestHandlerCallbackErrorKeepsRedirect(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, nil)
	router := newTestRouter(env)

	authURL, stateCookie, err := env.service.StartLogin(t.Context(), provider.ID, "/interaction?interaction=abc")
	require.NoError(t, err)
	_, state := env.provider.authorize(t, authURL, fakeAccount{Subject: "leo"})

	// The user cancelled at the provider, so the sign-in page shows the error and keeps the destination for the next attempt
	res := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, callbackPath+"?"+url.Values{"error": {"access_denied"}, "state": {state}}.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: cookie.IdentityProviderStateCookieName, Value: stateCookie, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	router.ServeHTTP(res, req)
	require.Equal(t, http.StatusFound, res.Code)

	location, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/login", location.Path)
	assert.Equal(t, "identity_provider_error", location.Query().Get("identityProviderError"))
	assert.Equal(t, "/interaction?interaction=abc", location.Query().Get("redirect"))
}

func TestHandlerLinkFlow(t *testing.T) {
	env := newTestEnv(t)
	provider := env.createProvider(t, nil)
	user := env.createUser(t, "mia", "mia@example.com")
	router := newTestRouter(env)

	// Starting to link requires the signed-in user, whose ID ends up in the state
	res := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/identity-providers/"+provider.ID+"/link", nil)
	req.Header.Set("X-Test-User", user.ID)
	router.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())

	var start startResponseDto
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &start))
	stateCookie := findCookie(res.Result(), cookie.IdentityProviderStateCookieName)
	require.NotNil(t, stateCookie)

	// The callback links the account and returns to the account settings without creating a new session
	code, state := env.provider.authorize(t, start.URL, fakeAccount{Subject: "mia-external"})
	res = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, callbackPath+"?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil)
	req.Header.Set("X-Test-User", user.ID)
	req.AddCookie(stateCookie)
	router.ServeHTTP(res, req)
	require.Equal(t, http.StatusFound, res.Code)
	assert.Equal(t, accountSettingsPath+"?identityProviderLinked=true", res.Header().Get("Location"))
	assert.Nil(t, findCookie(res.Result(), cookie.AccessTokenCookieName))

	// The user sees the link in the account settings
	res = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/users/me/identity-provider-links", nil)
	req.Header.Set("X-Test-User", user.ID)
	router.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)

	var links []linkDto
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &links))
	require.Len(t, links, 1)
	assert.Equal(t, "mia-external", links[0].Subject)
	assert.Equal(t, provider.ID, links[0].IdentityProvider.ID)
}
