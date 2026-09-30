<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Separator } from '$lib/components/ui/separator';
	import { m } from '$lib/paraglide/messages';
	import IdentityProviderService from '$lib/services/identity-provider-service';
	import type { PublicIdentityProvider } from '$lib/types/identity-provider.type';
	import { axiosErrorToast } from '$lib/utils/error-util';
	import { LucideLogIn } from '@lucide/svelte';
	import { onMount } from 'svelte';
	import { fade } from 'svelte/transition';

	let {
		redirect
	}: {
		// Where the browser returns to after signing in at the identity provider
		redirect: string;
	} = $props();

	const identityProviderService = new IdentityProviderService();

	let providers = $state<PublicIdentityProvider[]>([]);
	let loadingProviderId = $state<string | null>(null);

	onMount(async () => {
		// The buttons are optional, so a failure to load them must not break the sign-in page
		providers = await identityProviderService.listPublic().catch(() => []);
	});

	async function signIn(provider: PublicIdentityProvider) {
		loadingProviderId = provider.id;
		try {
			window.location.href = await identityProviderService.startLogin(provider.id, redirect);
		} catch (e) {
			axiosErrorToast(e);
			loadingProviderId = null;
		}
	}
</script>

{#if providers.length > 0}
	<div class="mt-8 flex w-full max-w-[450px] flex-col items-center gap-4" in:fade>
		<div class="flex w-full items-center gap-3">
			<Separator class="flex-1" />
			<span class="text-muted-foreground text-xs">{m.or_continue_with()}</span>
			<Separator class="flex-1" />
		</div>
		<div class="flex w-full flex-col items-center gap-2" data-testid="identity-provider-buttons">
			{#each providers as provider (provider.id)}
				<Button
					variant="outline"
					class="w-[80%] sm:w-[60%]"
					isLoading={loadingProviderId === provider.id}
					disabled={loadingProviderId !== null}
					onclick={() => signIn(provider)}
				>
					<LucideLogIn class="mr-1" />
					{m.sign_in_with_name({ name: provider.name })}
				</Button>
			{/each}
		</div>
	</div>
{/if}
