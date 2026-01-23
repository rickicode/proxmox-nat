<script>
    import { api } from '$lib/api';
    import { onMount } from 'svelte';
    import Icon from '$lib/components/Icon.svelte';

    let vms = $state([]);
    let loading = $state(true);
    let refreshing = $state(false);

    async function loadVMs() {
        loading = true;
        try {
            const res = await api.get('/vms');
            if (res.success) {
                vms = res.data || [];
            }
        } catch (e) {
            console.error(e);
        } finally {
            loading = false;
        }
    }

    async function refreshDiscovery() {
        refreshing = true;
        try {
            const res = await api.post('/vms/refresh');
            if (res.success) {
                // Background refresh started
                // Wait a bit then reload to see if updates are ready, or just show current cache
                setTimeout(loadVMs, 2000); 
            }
        } catch (e) {
            console.error('Failed to trigger refresh:', e);
        } finally {
            refreshing = false;
        }
    }

    onMount(loadVMs);
</script>

<div class="space-y-6">
    <div class="flex justify-between items-center">
        <div>
            <h2 class="text-2xl font-bold text-gray-800 dark:text-white">VM Discovery</h2>
            <p class="text-gray-500 dark:text-gray-400 text-sm">Automatically discovered VMs and Containers from Proxmox</p>
        </div>
        <button 
            onclick={refreshDiscovery}
            disabled={refreshing}
            class="flex items-center gap-2 px-4 py-2 bg-white dark:bg-dark-surface border border-gray-200 dark:border-dark-border text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-border transition-colors disabled:opacity-50"
        >
            <Icon icon="mdi:refresh" class={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            <span>{refreshing ? 'Scanning...' : 'Scan Now'}</span>
        </button>
    </div>

    {#if loading}
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {#each Array(3) as _}
                <div class="h-40 bg-gray-100 dark:bg-dark-surface rounded-xl animate-pulse"></div>
            {/each}
        </div>
    {:else}
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {#each vms as vm}
                <div class="glass-panel p-6 rounded-xl flex flex-col group relative overflow-hidden">
                    <div class="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-primary-500/10 to-transparent blur-2xl -mr-16 -mt-16 pointer-events-none"></div>
                    <div class="flex items-start justify-between mb-4 relative z-10">
                        <div class={`p-3 rounded-lg ${vm.type === 'lxc' ? 'bg-purple-100 text-purple-600 dark:bg-purple-900/20 dark:text-purple-400' : 'bg-blue-100 text-blue-600 dark:bg-blue-900/20 dark:text-blue-400'}`}>
                            {#if vm.type === 'lxc'}
                                <Icon icon="mdi:harddisk" class="w-6 h-6" />
                            {:else}
                                <Icon icon="mdi:monitor" class="w-6 h-6" />
                            {/if}
                        </div>
                        <span class={`px-2 py-1 rounded text-xs font-bold uppercase ${vm.status === 'running' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'}`}>
                            {vm.status}
                        </span>
                    </div>

                    <h3 class="text-lg font-bold text-gray-900 dark:text-white mb-1">{vm.name}</h3>
                    <p class="text-sm text-gray-500 dark:text-gray-400 mb-4">ID: {vm.id}</p>

                    <div class="space-y-2 pt-4 border-t border-gray-100 dark:border-dark-border">
                        <div class="flex justify-between text-sm">
                            <span class="text-gray-500">IP Address</span>
                            <span class="font-mono text-gray-900 dark:text-white">{vm.ip || 'Unknown'}</span>
                        </div>
                        <div class="flex justify-between text-sm">
                            <span class="text-gray-500">Type</span>
                            <span class="uppercase text-gray-900 dark:text-white">{vm.type}</span>
                        </div>
                    </div>
                </div>
            {/each}

            {#if vms.length === 0}
                <div class="col-span-full text-center py-12 bg-white dark:bg-dark-surface rounded-xl border border-dashed border-gray-300 dark:border-dark-border">
                    <Icon icon="mdi:server-off" class="w-12 h-12 mx-auto mb-3 text-gray-300" />
                    <p class="text-gray-500">No VMs found. Try scanning again.</p>
                </div>
            {/if}
        </div>
    {/if}
</div>
