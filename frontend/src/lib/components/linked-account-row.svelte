<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as Item from '$lib/components/ui/item/index.js';
	import * as Tooltip from '$lib/components/ui/tooltip/index.js';
	import { m } from '$lib/paraglide/messages';
	import type { IdentityProviderLink } from '$lib/types/identity-provider.type';
	import { LucideCalendar, LucideLogIn, LucideUnlink } from '@lucide/svelte';

	let {
		link,
		onUnlink
	}: {
		link: IdentityProviderLink;
		onUnlink: () => void;
	} = $props();
</script>

<Item.Root variant="transparent" class="hover:bg-muted transition-colors py-3 px-0 sm:px-4">
	<Item.Media class="bg-muted text-muted-foreground size-11 rounded-xl">
		<LucideLogIn class="size-6" />
	</Item.Media>
	<Item.Content class="gap-0.5">
		<Item.Title>{link.identityProvider.name}</Item.Title>
		<Item.Description class="flex flex-wrap items-center gap-x-3">
			{#if link.email}
				<span class="break-all">{link.email}</span>
			{/if}
			<span class="flex items-center">
				<LucideCalendar class="mr-1 size-3" />
				{m.linked_on()}
				{new Date(link.createdAt).toLocaleDateString()}
			</span>
		</Item.Description>
	</Item.Content>
	<Item.Actions>
		<Tooltip.Provider>
			<Tooltip.Root>
				<Tooltip.Trigger>
					<Button
						onclick={onUnlink}
						size="icon"
						variant="ghost"
						class="hover:bg-destructive/10 hover:text-destructive size-8"
						aria-label={m.unlink()}
					>
						<LucideUnlink class="size-4" />
					</Button>
				</Tooltip.Trigger>
				<Tooltip.Content>{m.unlink()}</Tooltip.Content>
			</Tooltip.Root>
		</Tooltip.Provider>
	</Item.Actions>
</Item.Root>
