export type IdentityProvider = {
	id: string;
	name: string;
	enabled: boolean;
	issuer: string;
	clientId: string;
	hasClientSecret: boolean;
	scopes: string;
	autoCreateUsers: boolean;
	autoLinkUsers: boolean;
	autoUpdateUsers: boolean;
	createdAt: string;
};

export type IdentityProviderInput = {
	name: string;
	enabled: boolean;
	issuer: string;
	clientId: string;
	// Omitted to keep the stored secret when updating
	clientSecret?: string;
	scopes: string;
	autoCreateUsers: boolean;
	autoLinkUsers: boolean;
	autoUpdateUsers: boolean;
};

export type PublicIdentityProvider = {
	id: string;
	name: string;
};

export type IdentityProviderLink = {
	id: string;
	identityProvider: PublicIdentityProvider;
	subject: string;
	email?: string;
	createdAt: string;
	lastUsedAt?: string;
};
