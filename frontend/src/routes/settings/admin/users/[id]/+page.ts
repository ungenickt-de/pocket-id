import IdentityProviderService from '$lib/services/identity-provider-service';
import UserService from '$lib/services/user-service';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params }) => {
	const userService = new UserService();
	const identityProviderService = new IdentityProviderService();
	const [user, passkeys, identityProviderLinks] = await Promise.all([
		userService.get(params.id),
		userService.listUserPasskeys(params.id),
		identityProviderService.listUserLinks(params.id)
	]);

	return {
		user,
		passkeys,
		identityProviderLinks
	};
};
