import type { PageLoad } from './$types';

export const load: PageLoad = async ({ url }) => {
	return {
		redirect: url.searchParams.get('redirect') || '/settings',
		// Set by the backend when a sign-in with an identity provider failed
		identityProviderError: url.searchParams.get('identityProviderError')
	};
};
