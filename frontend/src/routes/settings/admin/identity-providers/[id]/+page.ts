import IdentityProviderService from '$lib/services/identity-provider-service';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params }) => {
	const provider = await new IdentityProviderService().get(params.id);
	return { provider };
};
