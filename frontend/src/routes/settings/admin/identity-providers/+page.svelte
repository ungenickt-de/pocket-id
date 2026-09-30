<script lang="ts">
	import { goto } from '$app/navigation';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { m } from '$lib/paraglide/messages';
	import IdentityProviderService from '$lib/services/identity-provider-service';
	import type { IdentityProviderInput } from '$lib/types/identity-provider.type';
	import { LucideLogIn, LucideMinus, LucidePlus } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import { slide } from 'svelte/transition';
	import IdentityProviderForm from './identity-provider-form.svelte';
	import IdentityProviderList from './identity-provider-list.svelte';

	let expandAddProvider = $state(false);

	const identityProviderService = new IdentityProviderService();

	async function createProvider(provider: IdentityProviderInput) {
		const createdProvider = await identityProviderService.create(provider);
		toast.success(m.identity_provider_created_successfully());
		goto(`/settings/admin/identity-providers/${createdProvider.id}`);
	}
</script>

<svelte:head>
	<title>{m.identity_providers()}</title>
</svelte:head>

<div>
	<Card.Root>
		<Card.Header>
			<div class="flex flex-wrap items-center justify-between gap-4 md:flex-nowrap">
				<div>
					<Card.Title>
						<LucidePlus class="text-primary/80 size-5" />
						{m.create_identity_provider()}
					</Card.Title>
					<Card.Description>{m.create_identity_provider_description()}</Card.Description>
				</div>
				{#if !expandAddProvider}
					<Button class="w-full md:w-auto" onclick={() => (expandAddProvider = true)}>
						{m.add_identity_provider()}
					</Button>
				{:else}
					<Button class="h-8 p-3" variant="ghost" onclick={() => (expandAddProvider = false)}>
						<LucideMinus class="size-5" />
					</Button>
				{/if}
			</div>
		</Card.Header>
		{#if expandAddProvider}
			<div transition:slide>
				<Card.Content>
					<IdentityProviderForm callback={createProvider} />
				</Card.Content>
			</div>
		{/if}
	</Card.Root>
</div>

<div>
	<Card.Root>
		<Card.Header>
			<Card.Title>
				<LucideLogIn class="text-primary/80 size-5" />
				{m.manage_identity_providers()}
			</Card.Title>
		</Card.Header>
		<Card.Content>
			<IdentityProviderList />
		</Card.Content>
	</Card.Root>
</div>
