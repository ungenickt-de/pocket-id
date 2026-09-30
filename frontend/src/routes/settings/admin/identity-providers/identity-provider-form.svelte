<script lang="ts">
	import { page } from '$app/state';
	import CopyToClipboard from '$lib/components/copy-to-clipboard.svelte';
	import FormInput from '$lib/components/form/form-input.svelte';
	import SwitchWithLabel from '$lib/components/form/switch-with-label.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Field from '$lib/components/ui/field';
	import { m } from '$lib/paraglide/messages';
	import { IDENTITY_PROVIDER_CALLBACK_PATH } from '$lib/services/identity-provider-service';
	import type { IdentityProvider, IdentityProviderInput } from '$lib/types/identity-provider.type';
	import { axiosErrorToast } from '$lib/utils/error-util';
	import { preventDefault } from '$lib/utils/event-util';
	import { createForm } from '$lib/utils/form-util';
	import { trackFormChanges } from '$lib/utils/unsaved-changes-util.svelte';
	import { z } from 'zod/v4';

	let {
		callback,
		existingProvider
	}: {
		existingProvider?: IdentityProvider;
		callback: (provider: IdentityProviderInput) => Promise<void>;
	} = $props();

	let isLoading = $state(false);
	const isEdit = !!existingProvider;

	// The backend never returns the client secret, so the field starts empty and an empty value keeps the stored secret
	const provider = {
		name: existingProvider?.name || '',
		enabled: existingProvider?.enabled ?? true,
		issuer: existingProvider?.issuer || '',
		clientId: existingProvider?.clientId || '',
		clientSecret: '',
		scopes: existingProvider?.scopes || 'openid profile email',
		autoCreateUsers: existingProvider?.autoCreateUsers ?? false,
		autoLinkUsers: existingProvider?.autoLinkUsers ?? false,
		autoUpdateUsers: existingProvider?.autoUpdateUsers ?? false
	};

	const formSchema = z.object({
		name: z.string().min(1).max(50),
		enabled: z.boolean(),
		issuer: z.url().max(350),
		clientId: z.string().min(1).max(350),
		clientSecret: z.string().max(1000),
		scopes: z.string().max(500),
		autoCreateUsers: z.boolean(),
		autoLinkUsers: z.boolean(),
		autoUpdateUsers: z.boolean()
	});
	type FormSchema = typeof formSchema;

	const formStore = createForm<FormSchema>(formSchema, provider);
	const { inputs } = formStore;

	const callbackUrl = page.url.origin + IDENTITY_PROVIDER_CALLBACK_PATH;

	async function saveProvider(data: z.infer<FormSchema>) {
		await callback({ ...data, clientSecret: data.clientSecret || undefined });
		if (!existingProvider) formStore.reset();
	}

	// Create mode has its own Save button rather than going through the unsaved-changes bar
	async function onSubmit() {
		const data = formStore.validate();
		if (!data) return;
		isLoading = true;
		try {
			await saveProvider(data);
		} catch (e) {
			axiosErrorToast(e);
		} finally {
			isLoading = false;
		}
	}

	if (isEdit) {
		trackFormChanges(() => formStore, saveProvider);
	}
</script>

<form onsubmit={preventDefault(onSubmit)}>
	<div class="flex flex-col gap-3">
		<div class="mb-2 flex flex-col sm:flex-row sm:items-center">
			<Field.Label class="w-52">{m.redirect_uri()}</Field.Label>
			<CopyToClipboard value={callbackUrl}>
				<span class="text-muted-foreground text-sm break-all" data-testid="callback-url">
					{callbackUrl}
				</span>
			</CopyToClipboard>
		</div>
		<p class="text-muted-foreground -mt-3 mb-2 text-xs">
			{m.identity_provider_callback_url_description()}
		</p>
		<div class="grid grid-cols-1 gap-x-3 gap-y-3 sm:grid-cols-2">
			<FormInput
				label={m.name()}
				description={m.identity_provider_name_description()}
				placeholder="Zitadel"
				bind:input={$inputs.name}
			/>
			<FormInput
				label={m.issuer()}
				description={m.identity_provider_issuer_description()}
				placeholder="https://auth.example.com"
				bind:input={$inputs.issuer}
			/>
			<FormInput
				label={m.client_id()}
				description={m.identity_provider_client_id_description()}
				bind:input={$inputs.clientId}
			/>
			<FormInput
				label={m.client_secret()}
				description={existingProvider?.hasClientSecret
					? m.identity_provider_client_secret_stored_description()
					: m.identity_provider_client_secret_description()}
				type="password"
				placeholder={existingProvider?.hasClientSecret ? '••••••••' : ''}
				bind:input={$inputs.clientSecret}
			/>
			<FormInput
				class="sm:col-span-2"
				label={m.scopes()}
				description={m.identity_provider_scopes_description()}
				bind:input={$inputs.scopes}
			/>
		</div>
		<div class="mt-3 grid grid-cols-1 gap-x-3 gap-y-5 sm:grid-cols-2">
			<SwitchWithLabel
				id="identity-provider-enabled"
				label={m.enabled()}
				description={m.identity_provider_enabled_description()}
				bind:checked={$inputs.enabled.value}
			/>
			<SwitchWithLabel
				id="identity-provider-auto-create"
				label={m.auto_create_users()}
				description={m.auto_create_users_description()}
				bind:checked={$inputs.autoCreateUsers.value}
			/>
			<SwitchWithLabel
				id="identity-provider-auto-link"
				label={m.auto_link_users()}
				description={m.auto_link_users_description()}
				bind:checked={$inputs.autoLinkUsers.value}
			/>
			<SwitchWithLabel
				id="identity-provider-auto-update"
				label={m.auto_update_users()}
				description={m.auto_update_users_description()}
				bind:checked={$inputs.autoUpdateUsers.value}
			/>
		</div>
	</div>
	{#if !isEdit}
		<div class="mt-5 flex justify-end">
			<Button {isLoading} type="submit">{m.save()}</Button>
		</div>
	{/if}
</form>
