package identityprovider

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	cryptoutils "github.com/pocket-id/pocket-id/backend/internal/utils/crypto"
)

const (
	// loginStateTTL is how long a user has to complete the sign-in at the identity provider
	loginStateTTL = 10 * time.Minute
	// loginStateAAD binds the encrypted state to its purpose, so no other ciphertext produced with the same key is accepted
	loginStateAAD = "identity_provider_login_state"
	// loginStateKeySeed derives the key used to encrypt the state from the master encryption key
	loginStateKeySeed = "identity_provider_login_state"

	defaultRedirect = "/settings"
)

// flowMode distinguishes a sign-in from linking an external account to the signed-in user
type flowMode string

const (
	flowModeLogin flowMode = "login"
	flowModeLink  flowMode = "link"
)

// loginState is everything Pocket ID has to remember between sending the browser to the identity provider and receiving the callback
// It's kept in an encrypted cookie in the browser, so no server-side storage is needed and the flow is bound to the browser that started it
type loginState struct {
	ProviderID   string    `json:"p"`
	State        string    `json:"s"`
	Nonce        string    `json:"n"`
	CodeVerifier string    `json:"v"`
	Redirect     string    `json:"r,omitempty"`
	Mode         flowMode  `json:"m"`
	UserID       string    `json:"u,omitempty"`
	ExpiresAt    time.Time `json:"e"`
}

// stateCodec encrypts and decrypts the login state
type stateCodec struct {
	key []byte
	now func() time.Time
}

func newStateCodec(masterKey []byte) (*stateCodec, error) {
	key, err := cryptoutils.DeriveKey(masterKey, loginStateKeySeed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive the identity provider state key: %w", err)
	}

	return &stateCodec{key: key, now: time.Now}, nil
}

// Encode encrypts the state into a value that is safe to store in a cookie
func (c *stateCodec) Encode(state loginState) (string, error) {
	plaintext, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("failed to encode login state: %w", err)
	}

	ciphertext, err := cryptoutils.Encrypt(c.key, plaintext, []byte(loginStateAAD))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt login state: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Decode decrypts the state from the cookie and checks it belongs to the callback that is being processed
func (c *stateCodec) Decode(value, expectedState string) (loginState, error) {
	if value == "" || expectedState == "" {
		return loginState{}, errors.New("login state is missing")
	}

	// Decrypt the cookie, which also proves Pocket ID created it
	ciphertext, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return loginState{}, fmt.Errorf("failed to decode login state: %w", err)
	}
	plaintext, err := cryptoutils.Decrypt(c.key, ciphertext, []byte(loginStateAAD))
	if err != nil {
		return loginState{}, fmt.Errorf("failed to decrypt login state: %w", err)
	}

	var state loginState
	err = json.Unmarshal(plaintext, &state)
	if err != nil {
		return loginState{}, fmt.Errorf("failed to parse login state: %w", err)
	}

	// The state parameter returned by the identity provider must be the one stored in this browser, which prevents login CSRF
	if subtle.ConstantTimeCompare([]byte(state.State), []byte(expectedState)) != 1 {
		return state, errors.New("state parameter does not match")
	}
	if c.now().After(state.ExpiresAt) {
		return state, errors.New("login state has expired")
	}

	return state, nil
}

// sanitizeRedirect only accepts paths on Pocket ID itself, so the sign-in cannot be abused as an open redirect
func sanitizeRedirect(redirect string) string {
	// Only absolute paths are allowed, and protocol-relative URLs like "//evil.example" are rejected
	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		return defaultRedirect
	}

	// Browsers treat backslashes like slashes and drop tabs and newlines, so "/\evil.example" or "/\t/evil.example" would become protocol-relative
	if strings.ContainsFunc(redirect, func(r rune) bool { return r == '\\' || r < 0x20 || r == 0x7f }) {
		return defaultRedirect
	}

	parsed, err := url.Parse(redirect)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" {
		return defaultRedirect
	}

	return redirect
}
