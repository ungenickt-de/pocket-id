import IdentityProviderService from '$lib/services/identity-provider-service';
import UserService from '$lib/services/user-service';
import WebAuthnService from '$lib/services/webauthn-service';
import type { PageLoad } from './$types';

export const load: PageLoad = async () => {
	const webauthnService = new WebAuthnService();
	const userService = new UserService();
	const identityProviderService = new IdentityProviderService();

	const [account, passkeys, identityProviders, identityProviderLinks] = await Promise.all([
		userService.getCurrent(),
		webauthnService.listCredentials(),
		identityProviderService.listPublic(),
		identityProviderService.listOwnLinks()
	]);

	return {
		account,
		passkeys,
		identityProviders,
		identityProviderLinks
	};
};
