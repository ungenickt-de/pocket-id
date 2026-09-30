<script lang="ts">
	import { goto } from '$app/navigation';
	import { openConfirmDialog } from '$lib/components/confirm-dialog/';
	import AdvancedTable from '$lib/components/table/advanced-table.svelte';
	import { m } from '$lib/paraglide/messages';
	import IdentityProviderService from '$lib/services/identity-provider-service';
	import type {
		AdvancedTableColumn,
		CreateAdvancedTableActions
	} from '$lib/types/advanced-table.type';
	import type { IdentityProvider } from '$lib/types/identity-provider.type';
	import { axiosErrorToast } from '$lib/utils/error-util';
	import { LucidePencil, LucideTrash } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';

	const identityProviderService = new IdentityProviderService();
	let tableRef: AdvancedTable<IdentityProvider>;

	export function refresh() {
		return tableRef?.refresh();
	}

	const columns: AdvancedTableColumn<IdentityProvider>[] = [
		{ label: 'ID', column: 'id', hidden: true },
		{ label: m.name(), column: 'name', sortable: true },
		{ label: m.issuer(), column: 'issuer', sortable: true },
		{
			label: m.status(),
			column: 'enabled',
			sortable: true,
			value: (item) => (item.enabled ? m.enabled() : m.disabled())
		}
	];

	const actions: CreateAdvancedTableActions<IdentityProvider> = () => [
		{
			label: m.edit(),
			primary: true,
			icon: LucidePencil,
			variant: 'ghost',
			onClick: (provider) => goto(`/settings/admin/identity-providers/${provider.id}`)
		},
		{
			label: m.delete(),
			icon: LucideTrash,
			variant: 'danger',
			onClick: (provider) => deleteProvider(provider)
		}
	];

	async function deleteProvider(provider: IdentityProvider) {
		openConfirmDialog({
			title: m.delete_name({ name: provider.name }),
			message: m.are_you_sure_you_want_to_delete_this_identity_provider(),
			confirm: {
				label: m.delete(),
				destructive: true,
				action: async () => {
					try {
						await identityProviderService.remove(provider.id);
						await refresh();
						toast.success(m.identity_provider_deleted_successfully());
					} catch (e) {
						axiosErrorToast(e);
					}
				}
			}
		});
	}
</script>

<AdvancedTable
	id="identity-provider-list"
	bind:this={tableRef}
	fetchCallback={identityProviderService.list}
	defaultSort={{ column: 'name', direction: 'asc' }}
	{columns}
	{actions}
/>
