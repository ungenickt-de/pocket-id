<script lang="ts">
	import * as Card from '$lib/components/ui/card';
	import { m } from '$lib/paraglide/messages';
	import IdentityProviderService from '$lib/services/identity-provider-service';
	import type { IdentityProviderInput } from '$lib/types/identity-provider.type';
	import { LucideChevronLeft } from '@lucide/svelte';
	import { backNavigate } from '../../users/navigate-back-util';
	import IdentityProviderForm from '../identity-provider-form.svelte';

	let { data } = $props();
	let provider = $state(data.provider);

	const identityProviderService = new IdentityProviderService();
	const backNavigation = backNavigate('/settings/admin/identity-providers');

	async function updateProvider(updated: IdentityProviderInput) {
		provider = await identityProviderService.update(provider.id, updated);
	}
</script>

<svelte:head>
	<title>{provider.name}</title>
</svelte:head>

<div>
	<button type="button" class="text-muted-foreground flex text-sm" onclick={backNavigation.go}>
		<LucideChevronLeft class="size-5" />
		{m.back()}
	</button>
</div>

<Card.Root>
	<Card.Header>
		<Card.Title>{m.general()}</Card.Title>
	</Card.Header>
	<Card.Content>
		<IdentityProviderForm existingProvider={provider} callback={updateProvider} />
	</Card.Content>
</Card.Root>
