<script lang="ts">
	import { afterNavigate, replaceState } from '$app/navigation';
	import { page } from '$app/state';
	import { openConfirmDialog } from '$lib/components/confirm-dialog/';
	import LinkedAccountRow from '$lib/components/linked-account-row.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Item from '$lib/components/ui/item/index.js';
	import { m } from '$lib/paraglide/messages';
	import IdentityProviderService from '$lib/services/identity-provider-service';
	import type {
		IdentityProviderLink,
		PublicIdentityProvider
	} from '$lib/types/identity-provider.type';
	import { axiosErrorToast, getErrorCodeMessage } from '$lib/utils/error-util';
	import { LucideLink } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';

	let {
		providers,
		links = $bindable()
	}: {
		providers: PublicIdentityProvider[];
		links: IdentityProviderLink[];
	} = $props();

	const identityProviderService = new IdentityProviderService();

	// A user can link one account per provider, so only providers without a link are offered
	const unlinkedProviders = $derived(
		providers.filter((provider) => !links.some((link) => link.identityProvider.id === provider.id))
	);

	// The backend returns here after linking, with the outcome in the query string
	// It's handled after the navigation, since the URL can only be replaced once the router is ready
	afterNavigate(() => {
		const params = page.url.searchParams;
		const errorCode = params.get('identityProviderError');
		if (params.get('identityProviderLinked')) {
			toast.success(m.account_linked_successfully());
		} else if (errorCode) {
			toast.error(getErrorCodeMessage(errorCode));
		} else {
			return;
		}

		// Drop the outcome from the URL so it isn't shown again on reload
		const url = new URL(page.url);
		url.searchParams.delete('identityProviderLinked');
		url.searchParams.delete('identityProviderError');
		replaceState(url, page.state);
	});

	async function startLink(provider: PublicIdentityProvider) {
		try {
			window.location.href = await identityProviderService.startLink(provider.id);
		} catch (e) {
			axiosErrorToast(e);
		}
	}

	function unlink(linkToRemove: IdentityProviderLink) {
		openConfirmDialog({
			title: m.unlink_name({ name: linkToRemove.identityProvider.name }),
			message: m.are_you_sure_you_want_to_unlink_this_account(),
			confirm: {
				label: m.unlink(),
				destructive: true,
				action: async () => {
					try {
						await identityProviderService.removeOwnLink(linkToRemove.id);
						links = await identityProviderService.listOwnLinks();
						toast.success(m.account_unlinked_successfully());
					} catch (e) {
						axiosErrorToast(e);
					}
				}
			}
		});
	}
</script>

{#if providers.length > 0 || links.length > 0}
	<Item.Group class="bg-card border shadow-sm rounded-4xl p-5" data-testid="linked-accounts">
		<Item.Root class="border-none bg-transparent p-0">
			<Item.Media class="text-primary/80">
				<LucideLink class="size-5" />
			</Item.Media>
			<Item.Content class="min-w-52">
				<Item.Title class="text-xl font-semibold">{m.linked_accounts()}</Item.Title>
				<Item.Description>{m.linked_accounts_description()}</Item.Description>
			</Item.Content>
			{#if unlinkedProviders.length > 0}
				<Item.Actions class="flex-wrap">
					{#each unlinkedProviders as provider (provider.id)}
						<Button variant="outline" usePromiseLoading onclick={() => startLink(provider)}>
							{m.link_name({ name: provider.name })}
						</Button>
					{/each}
				</Item.Actions>
			{/if}
		</Item.Root>
		{#if links.length > 0}
			<Item.Group class="mt-3">
				{#each links as link (link.id)}
					<LinkedAccountRow {link} onUnlink={() => unlink(link)} />
				{/each}
			</Item.Group>
		{/if}
	</Item.Group>
{/if}
