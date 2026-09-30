package identityprovider

import (
	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
)

// IdentityProvider is an external OpenID Connect provider users can sign in with
type IdentityProvider struct {
	model.Base

	Name         string `sortable:"case-insensitive"`
	Enabled      bool   `sortable:"true" filterable:"true"`
	Issuer       string `sortable:"case-insensitive"`
	ClientID     string
	ClientSecret datatype.EncryptedString
	Scopes       string

	// AutoCreateUsers creates a local user the first time an unknown external account signs in
	AutoCreateUsers bool
	// AutoLinkUsers links an unknown external account to the local user with the same verified email address
	AutoLinkUsers bool
	// AutoUpdateUsers copies the profile of the external account to the linked local user on every sign-in
	AutoUpdateUsers bool

	UpdatedAt *datatype.DateTime
}

func (IdentityProvider) TableName() string {
	return "identity_providers"
}

// Link ties an account at an external identity provider to a local user
type Link struct {
	model.Base

	UserID             string
	IdentityProviderID string
	IdentityProvider   IdentityProvider `gorm:"foreignKey:IdentityProviderID;references:ID"`

	// Subject is the stable identifier of the account at the identity provider (the "sub" claim)
	Subject string
	// Email is the email address the identity provider reported at the last sign-in, kept to help users recognize the account
	Email      *string
	LastUsedAt *datatype.DateTime `sortable:"true"`
}

func (Link) TableName() string {
	return "identity_provider_links"
}
