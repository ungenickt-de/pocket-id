import type {
	IdentityProvider,
	IdentityProviderInput,
	IdentityProviderLink,
	PublicIdentityProvider
} from '$lib/types/identity-provider.type';
import type { ListRequestOptions, Paginated } from '$lib/types/list-request.type';
import APIService from './api-service';

// The redirect URI all identity providers send the browser back to
export const IDENTITY_PROVIDER_CALLBACK_PATH = '/api/identity-providers/callback';

export default class IdentityProviderService extends APIService {
	list = async (options?: ListRequestOptions) => {
		const res = await this.api.get('/identity-providers', { params: options });
		return res.data as Paginated<IdentityProvider>;
	};

	get = async (id: string) => {
		const res = await this.api.get(`/identity-providers/${id}`);
		return res.data as IdentityProvider;
	};

	create = async (provider: IdentityProviderInput) => {
		const res = await this.api.post('/identity-providers', provider);
		return res.data as IdentityProvider;
	};

	update = async (id: string, provider: IdentityProviderInput) => {
		const res = await this.api.put(`/identity-providers/${id}`, provider);
		return res.data as IdentityProvider;
	};

	remove = async (id: string) => {
		await this.api.delete(`/identity-providers/${id}`);
	};

	listPublic = async () => {
		const res = await this.api.get('/identity-providers/public');
		return res.data as PublicIdentityProvider[];
	};

	// Returns the URL of the provider's sign-in page, the state is stored in a cookie by the backend
	startLogin = async (id: string, redirect: string) => {
		const res = await this.api.post(`/identity-providers/${id}/login`, { redirect });
		return res.data.url as string;
	};

	startLink = async (id: string) => {
		const res = await this.api.post(`/identity-providers/${id}/link`);
		return res.data.url as string;
	};

	listOwnLinks = async () => {
		const res = await this.api.get('/users/me/identity-provider-links');
		return res.data as IdentityProviderLink[];
	};

	removeOwnLink = async (linkId: string) => {
		await this.api.delete(`/users/me/identity-provider-links/${linkId}`);
	};

	listUserLinks = async (userId: string) => {
		const res = await this.api.get(`/users/${userId}/identity-provider-links`);
		return res.data as IdentityProviderLink[];
	};

	removeUserLink = async (userId: string, linkId: string) => {
		await this.api.delete(`/users/${userId}/identity-provider-links/${linkId}`);
	};
}
