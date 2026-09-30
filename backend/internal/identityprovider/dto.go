package identityprovider

import (
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
)

// identityProviderDto is the admin representation of an identity provider
// The client secret is never returned, only whether one is configured
type identityProviderDto struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Enabled         bool              `json:"enabled"`
	Issuer          string            `json:"issuer"`
	ClientID        string            `json:"clientId"`
	HasClientSecret bool              `json:"hasClientSecret"`
	Scopes          string            `json:"scopes"`
	AutoCreateUsers bool              `json:"autoCreateUsers"`
	AutoLinkUsers   bool              `json:"autoLinkUsers"`
	AutoUpdateUsers bool              `json:"autoUpdateUsers"`
	CreatedAt       datatype.DateTime `json:"createdAt"`
}

func newIdentityProviderDto(provider IdentityProvider) identityProviderDto {
	return identityProviderDto{
		ID:              provider.ID,
		Name:            provider.Name,
		Enabled:         provider.Enabled,
		Issuer:          provider.Issuer,
		ClientID:        provider.ClientID,
		HasClientSecret: provider.ClientSecret != "",
		Scopes:          provider.Scopes,
		AutoCreateUsers: provider.AutoCreateUsers,
		AutoLinkUsers:   provider.AutoLinkUsers,
		AutoUpdateUsers: provider.AutoUpdateUsers,
		CreatedAt:       provider.CreatedAt,
	}
}

// identityProviderInputDto is the payload for creating or updating an identity provider
// A nil client secret keeps the stored one on update, while an empty string removes it
type identityProviderInputDto struct {
	Name            string  `json:"name" binding:"required,min=1,max=50" unorm:"nfc"`
	Enabled         bool    `json:"enabled"`
	Issuer          string  `json:"issuer" binding:"required,url,max=350"`
	ClientID        string  `json:"clientId" binding:"required,min=1,max=350"`
	ClientSecret    *string `json:"clientSecret" binding:"omitempty,max=1000"`
	Scopes          string  `json:"scopes" binding:"max=500"`
	AutoCreateUsers bool    `json:"autoCreateUsers"`
	AutoLinkUsers   bool    `json:"autoLinkUsers"`
	AutoUpdateUsers bool    `json:"autoUpdateUsers"`
}

// publicIdentityProviderDto is what the sign-in page needs to render a button for an identity provider
type publicIdentityProviderDto struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// linkDto is an external account linked to a user
type linkDto struct {
	ID               string                    `json:"id"`
	IdentityProvider publicIdentityProviderDto `json:"identityProvider"`
	Subject          string                    `json:"subject"`
	Email            *string                   `json:"email"`
	CreatedAt        datatype.DateTime         `json:"createdAt"`
	LastUsedAt       *datatype.DateTime        `json:"lastUsedAt"`
}

func newLinkDtos(links []Link) []linkDto {
	dtos := make([]linkDto, len(links))
	for i, link := range links {
		dtos[i] = linkDto{
			ID: link.ID,
			IdentityProvider: publicIdentityProviderDto{
				ID:   link.IdentityProvider.ID,
				Name: link.IdentityProvider.Name,
			},
			Subject:    link.Subject,
			Email:      link.Email,
			CreatedAt:  link.CreatedAt,
			LastUsedAt: link.LastUsedAt,
		}
	}

	return dtos
}

// startDto is the payload for starting a sign-in with an identity provider
type startDto struct {
	Redirect string `json:"redirect" binding:"max=2000"`
}

// startResponseDto carries the authorization URL the browser has to be sent to
type startResponseDto struct {
	URL string `json:"url"`
}
