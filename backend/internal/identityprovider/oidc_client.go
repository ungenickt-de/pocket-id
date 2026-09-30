package identityprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jwx-go/jwkfetch/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"golang.org/x/oauth2"
)

const (
	// metadataCacheTTL is how long discovery documents and key sets are reused before they are fetched again
	metadataCacheTTL = time.Hour
	// keySetRefreshCooldown keeps a flood of invalid tokens from forcing a key set download on every request
	keySetRefreshCooldown = 30 * time.Second
	// maxResponseBodySize caps the size of discovery and userinfo responses
	maxResponseBodySize = 1 << 20
	// idTokenClockSkew is the tolerated clock difference between Pocket ID and the identity provider
	idTokenClockSkew = time.Minute
)

// discoveryDocument is the subset of the OpenID Provider metadata the sign-in flow needs
type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

type cachedDiscovery struct {
	document  discoveryDocument
	fetchedAt time.Time
}

type cachedKeySet struct {
	set       jwk.Set
	fetchedAt time.Time
}

// relyingParty talks to external OpenID Providers on behalf of Pocket ID
// It caches discovery documents and key sets in memory, since both change rarely and every sign-in needs them
type relyingParty struct {
	httpClient  *http.Client
	jwksFetcher *jwkfetch.Client
	now         func() time.Time

	lock      sync.Mutex
	discovery map[string]cachedDiscovery
	keySets   map[string]cachedKeySet
}

func newRelyingParty(httpClient *http.Client) *relyingParty {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	return &relyingParty{
		httpClient:  httpClient,
		jwksFetcher: jwkfetch.NewClient(jwkfetch.WithHTTPClient(httpClient)),
		now:         time.Now,
		discovery:   make(map[string]cachedDiscovery),
		keySets:     make(map[string]cachedKeySet),
	}
}

// discoveryURL returns the location of the discovery document for an issuer as defined by OpenID Connect Discovery 1.0
func discoveryURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
}

// issuersMatch compares issuers while tolerating a trailing slash, which providers are inconsistent about
func issuersMatch(a, b string) bool {
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}

// Discover loads the discovery document of an issuer, serving it from the cache while it's fresh
func (rp *relyingParty) Discover(ctx context.Context, issuer string) (discoveryDocument, error) {
	// Serve the cached document while it's fresh
	rp.lock.Lock()
	cached, ok := rp.discovery[issuer]
	rp.lock.Unlock()
	if ok && rp.now().Sub(cached.fetchedAt) < metadataCacheTTL {
		return cached.document, nil
	}

	// Download and validate the document
	var document discoveryDocument
	err := rp.getJSON(ctx, discoveryURL(issuer), "", &document)
	if err != nil {
		return discoveryDocument{}, fmt.Errorf("failed to load discovery document: %w", err)
	}

	// The issuer in the document must be the one that was configured, otherwise a different provider could be impersonated
	if !issuersMatch(document.Issuer, issuer) {
		return discoveryDocument{}, fmt.Errorf("discovery document issuer %q does not match the configured issuer %q", document.Issuer, issuer)
	}
	if document.AuthorizationEndpoint == "" || document.TokenEndpoint == "" || document.JWKSURI == "" {
		return discoveryDocument{}, errors.New("discovery document is missing the authorization endpoint, token endpoint or JWKS URI")
	}

	rp.lock.Lock()
	rp.discovery[issuer] = cachedDiscovery{document: document, fetchedAt: rp.now()}
	rp.lock.Unlock()

	return document, nil
}

// oauthConfig builds the OAuth 2.0 client configuration for an identity provider
func oauthConfig(provider IdentityProvider, document discoveryDocument, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret.String(),
		RedirectURL:  redirectURL,
		Scopes:       strings.Fields(provider.Scopes),
		Endpoint: oauth2.Endpoint{
			AuthURL:   document.AuthorizationEndpoint,
			TokenURL:  document.TokenEndpoint,
			AuthStyle: tokenEndpointAuthStyle(provider, document),
		},
	}
}

// tokenEndpointAuthStyle picks how the client authenticates at the token endpoint based on what the provider advertises
func tokenEndpointAuthStyle(provider IdentityProvider, document discoveryDocument) oauth2.AuthStyle {
	// Public clients rely on PKCE alone and only send their client ID in the request body
	if provider.ClientSecret == "" {
		return oauth2.AuthStyleInParams
	}

	// OpenID Connect defaults to client_secret_basic when the provider does not advertise its methods
	methods := document.TokenEndpointAuthMethodsSupported
	if len(methods) == 0 || slices.Contains(methods, "client_secret_basic") {
		return oauth2.AuthStyleInHeader
	}
	if slices.Contains(methods, "client_secret_post") {
		return oauth2.AuthStyleInParams
	}

	return oauth2.AuthStyleAutoDetect
}

// ExchangeCode redeems an authorization code at the token endpoint and returns the raw ID token and access token
func (rp *relyingParty) ExchangeCode(ctx context.Context, config *oauth2.Config, code, codeVerifier string) (idToken string, accessToken string, err error) {
	// The oauth2 package picks up the HTTP client from the context
	ctx = context.WithValue(ctx, oauth2.HTTPClient, rp.httpClient)

	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return "", "", fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	idToken, _ = token.Extra("id_token").(string)
	if idToken == "" {
		return "", "", errors.New("token response does not contain an ID token")
	}

	return idToken, token.AccessToken, nil
}

// VerifyIDToken validates the signature and the claims of an ID token as required by OpenID Connect Core 1.0 section 3.1.3.7
func (rp *relyingParty) VerifyIDToken(ctx context.Context, document discoveryDocument, clientID, rawIDToken, nonce string) (map[string]any, error) {
	// Verify the token with the cached keys first
	keySet, fetchedAt, err := rp.keySet(ctx, document.JWKSURI, false)
	if err != nil {
		return nil, err
	}
	token, err := parseIDToken(rawIDToken, keySet, document.Issuer, clientID)

	// The provider may have rotated its keys since they were cached, so retry once with a fresh key set
	if err != nil && rp.now().Sub(fetchedAt) > keySetRefreshCooldown {
		keySet, _, err = rp.keySet(ctx, document.JWKSURI, true)
		if err != nil {
			return nil, err
		}
		token, err = parseIDToken(rawIDToken, keySet, document.Issuer, clientID)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid ID token: %w", err)
	}

	claims, err := tokenClaims(token)
	if err != nil {
		return nil, err
	}

	// The nonce binds the ID token to the sign-in that was started in this browser
	tokenNonce, _ := claims["nonce"].(string)
	if tokenNonce == "" || tokenNonce != nonce {
		return nil, errors.New("invalid ID token: nonce does not match")
	}

	// When the authorized party is set, it must be Pocket ID, otherwise the token was issued to another client
	if azp, ok := claims["azp"].(string); ok && azp != "" && azp != clientID {
		return nil, fmt.Errorf("invalid ID token: authorized party %q does not match the client ID", azp)
	}

	return claims, nil
}

func parseIDToken(rawIDToken string, keySet jwk.Set, issuer, clientID string) (jwt.Token, error) {
	return jwt.Parse([]byte(rawIDToken),
		jwt.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true), jws.WithUseDefault(true)),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(idTokenClockSkew),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(clientID),
		jwt.WithRequiredClaim(jwt.SubjectKey),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
	)
}

// tokenClaims returns every claim of a parsed token as a plain map
func tokenClaims(token jwt.Token) (map[string]any, error) {
	encoded, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ID token claims: %w", err)
	}

	var claims map[string]any
	err = json.Unmarshal(encoded, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ID token claims: %w", err)
	}

	return claims, nil
}

// keySet returns the signing keys of a provider along with the time they were downloaded
func (rp *relyingParty) keySet(ctx context.Context, jwksURI string, forceRefresh bool) (jwk.Set, time.Time, error) {
	// Serve the cached keys while they're fresh
	rp.lock.Lock()
	cached, ok := rp.keySets[jwksURI]
	rp.lock.Unlock()
	if ok && !forceRefresh && rp.now().Sub(cached.fetchedAt) < metadataCacheTTL {
		return cached.set, cached.fetchedAt, nil
	}

	// Download the keys and remember them for the next sign-in
	set, err := rp.jwksFetcher.Fetch(ctx, jwksURI)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to load the signing keys of the identity provider: %w", err)
	}

	fetchedAt := rp.now()
	rp.lock.Lock()
	rp.keySets[jwksURI] = cachedKeySet{set: set, fetchedAt: fetchedAt}
	rp.lock.Unlock()

	return set, fetchedAt, nil
}

// FetchUserinfo loads the claims from the userinfo endpoint, since many providers only put a minimal set of claims into the ID token
// Signed or encrypted userinfo responses are not supported, in which case no additional claims are returned
func (rp *relyingParty) FetchUserinfo(ctx context.Context, document discoveryDocument, accessToken string) (map[string]any, error) {
	if document.UserinfoEndpoint == "" || accessToken == "" {
		return nil, nil
	}

	var claims map[string]any
	err := rp.getJSON(ctx, document.UserinfoEndpoint, accessToken, &claims)
	if errors.Is(err, errNotJSON) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to load userinfo: %w", err)
	}

	return claims, nil
}

var errNotJSON = errors.New("response is not JSON")

// getJSON performs a GET request and decodes the JSON response body into out
func (rp *relyingParty) getJSON(ctx context.Context, url, bearerToken string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	res, err := rp.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", url, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("request to %s returned status %d", url, res.StatusCode)
	}

	mediaType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if mediaType != "" && mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
		return errNotJSON
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBodySize))
	if err != nil {
		return fmt.Errorf("failed to read response from %s: %w", url, err)
	}

	err = json.Unmarshal(body, out)
	if err != nil {
		return fmt.Errorf("failed to decode response from %s: %w", url, err)
	}

	return nil
}
