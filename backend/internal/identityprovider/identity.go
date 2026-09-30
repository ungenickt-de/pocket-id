package identityprovider

import (
	"errors"
	"maps"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pocket-id/pocket-id/backend/internal/dto"
)

const (
	maxUsernameLength    = 50
	maxNameLength        = 50
	maxDisplayNameLength = 100
	fallbackUsername     = "user"
)

// profileClaims are the claims taken from the userinfo response in addition to the ID token
var profileClaims = []string{"email", "email_verified", "preferred_username", "name", "given_name", "family_name"}

// externalIdentity is the verified identity of an account at an identity provider
type externalIdentity struct {
	Subject           string
	Email             *string
	EmailVerified     bool
	PreferredUsername string
	Name              string
	GivenName         string
	FamilyName        string
}

// newExternalIdentity combines the claims of the ID token with the profile claims of the userinfo response
func newExternalIdentity(idTokenClaims map[string]any, userinfo map[string]any) (externalIdentity, error) {
	subject, _ := idTokenClaims["sub"].(string)
	if subject == "" {
		return externalIdentity{}, errors.New("ID token does not contain a subject")
	}

	// Userinfo claims are only trusted when they are about the same subject as the ID token, as required by OpenID Connect Core 1.0 section 5.3.2
	claims := maps.Clone(idTokenClaims)
	if userinfo != nil {
		userinfoSubject, _ := userinfo["sub"].(string)
		if userinfoSubject != subject {
			return externalIdentity{}, errors.New("userinfo subject does not match the ID token subject")
		}
		for _, key := range profileClaims {
			if value, ok := userinfo[key]; ok {
				claims[key] = value
			}
		}
	}

	identity := externalIdentity{
		Subject:           subject,
		EmailVerified:     boolClaim(claims["email_verified"]),
		PreferredUsername: stringClaim(claims["preferred_username"]),
		Name:              stringClaim(claims["name"]),
		GivenName:         stringClaim(claims["given_name"]),
		FamilyName:        stringClaim(claims["family_name"]),
	}

	// Addresses that are not plain email addresses are ignored rather than stored on the user
	email := stringClaim(claims["email"])
	if address, err := mail.ParseAddress(email); err == nil && address.Address == email {
		identity.Email = &email
	}

	return identity, nil
}

func stringClaim(value any) string {
	s, _ := value.(string)
	return strings.TrimSpace(s)
}

// boolClaim accepts booleans as well as the string "true", which some providers send for email_verified
func boolClaim(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}

// username derives a valid username from the profile, preferring the one the user chose at the provider
func (i externalIdentity) username() string {
	candidates := []string{i.PreferredUsername}
	if i.Email != nil {
		localPart, _, _ := strings.Cut(*i.Email, "@")
		candidates = append(candidates, localPart)
	}
	candidates = append(candidates, i.Name, strings.TrimSpace(i.GivenName+" "+i.FamilyName))

	for _, candidate := range candidates {
		username := sanitizeUsername(candidate)
		if username != "" && dto.ValidateUsername(username) {
			return username
		}
	}

	return fallbackUsername
}

// names returns the first, last and display name, splitting the full name when the provider does not return the parts
func (i externalIdentity) names() (firstName, lastName, displayName string) {
	firstName, lastName = i.GivenName, i.FamilyName
	if firstName == "" && lastName == "" && i.Name != "" {
		firstName, lastName, _ = strings.Cut(i.Name, " ")
		lastName = strings.TrimSpace(lastName)
	}

	displayName = i.Name
	if displayName == "" {
		displayName = strings.TrimSpace(firstName + " " + lastName)
	}

	return truncateRunes(firstName, maxNameLength), truncateRunes(lastName, maxNameLength), truncateRunes(displayName, maxDisplayNameLength)
}

// sanitizeUsername removes the characters usernames must not contain, turning spaces into dots
func sanitizeUsername(value string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(value) {
		switch {
		case r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)), r == '_', r == '.', r == '@', r == '-':
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteRune('.')
		}
	}

	return trimUsername(truncateRunes(b.String(), maxUsernameLength))
}

// trimUsername strips characters from both ends that usernames must not start or end with
func trimUsername(value string) string {
	return strings.TrimFunc(value, func(r rune) bool {
		return r >= unicode.MaxASCII || (!unicode.IsLetter(r) && !unicode.IsDigit(r))
	})
}

func truncateRunes(value string, maxLength int) string {
	if maxLength <= 0 {
		return ""
	}
	if utf8.RuneCountInString(value) <= maxLength {
		return value
	}

	return strings.TrimSpace(string([]rune(value)[:maxLength]))
}
