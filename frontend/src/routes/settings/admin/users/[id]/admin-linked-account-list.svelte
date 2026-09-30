<script lang="ts">
	import { openConfirmDialog } from '$lib/components/confirm-dialog';
	import LinkedAccountRow from '$lib/components/linked-account-row.svelte';
	import * as Item from '$lib/components/ui/item/index.js';
	import { m } from '$lib/paraglide/messages';
	import IdentityProviderService from '$lib/services/identity-provider-service';
	import type { IdentityProviderLink } from '$lib/types/identity-provider.type';
	import { axiosErrorToast } from '$lib/utils/error-util';
	import { toast } from 'svelte-sonner';

	let {
		userId,
		links = $bindable()
	}: {
		userId: string;
		links: IdentityProviderLink[];
	} = $props();

	const identityProviderService = new IdentityProviderService();

	function unlink(linkToRemove: IdentityProviderLink) {
		openConfirmDialog({
			title: m.unlink_name({ name: linkToRemove.identityProvider.name }),
			message: m.are_you_sure_you_want_to_unlink_this_account(),
			confirm: {
				label: m.unlink(),
				destructive: true,
				action: async () => {
					try {
						await identityProviderService.removeUserLink(userId, linkToRemove.id);
						links = await identityProviderService.listUserLinks(userId);
						toast.success(m.account_unlinked_successfully());
					} catch (e) {
						axiosErrorToast(e);
					}
				}
			}
		});
	}
</script>

<Item.Group class="mt-3">
	{#each links as link (link.id)}
		<LinkedAccountRow {link} onUnlink={() => unlink(link)} />
	{/each}
</Item.Group>
