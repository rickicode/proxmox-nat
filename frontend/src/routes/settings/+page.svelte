<script>
    import { api } from '$lib/api';
    import { onMount } from 'svelte';
    import Icon from '$lib/components/Icon.svelte';

    let status = $state({
        nat_enabled: false,
        forwarding_enabled: false,
        version: ''
    });

    let backups = $state([]);
    let loading = $state(false);

    async function loadStatus() {
        try {
            const res = await api.get('/status');
            if (res.success) {
                status = { ...status, ...res.data };
            }
            const ver = await api.get('/version');
            if (ver.success) {
                status.version = ver.data.version;
            }
            loadBackups();
        } catch (e) {
            console.error(e);
        }
    }

    async function loadBackups() {
        try {
            const res = await api.get('/backup/list');
            if (res.success) {
                backups = res.data || [];
            }
        } catch (e) {
            console.error(e);
        }
    }

    async function toggleNAT() {
        const action = status.nat_enabled ? 'disable' : 'enable';
        try {
            await api.post(`/nat/${action}`);
            status.nat_enabled = !status.nat_enabled;
        } catch (e) {
            alert(e.message);
        }
    }

    async function toggleForwarding() {
        const action = status.forwarding_enabled ? 'disable' : 'enable';
        try {
            await api.post(`/forwarding/${action}`);
            status.forwarding_enabled = !status.forwarding_enabled;
        } catch (e) {
            alert(e.message);
        }
    }

    async function createBackup() {
        const name = prompt('Enter backup name (optional):');
        if (name === null) return;
        
        try {
            await api.post('/backup/create', { name });
            loadBackups();
        } catch (e) {
            alert(e.message);
        }
    }

    async function restoreBackup(path) {
        if (!confirm('Are you sure? This will overwrite current rules.')) return;
        try {
            await api.post('/backup/restore', { backup_path: path, preview: false });
            alert('Backup restored successfully');
        } catch (e) {
            alert(e.message);
        }
    }

    onMount(loadStatus);
</script>

<div class="max-w-4xl mx-auto space-y-8">
    <h2 class="text-2xl font-bold text-gray-800 dark:text-white">System Settings</h2>

    <div class="bg-white dark:bg-dark-surface rounded-xl border border-gray-200 dark:border-dark-border shadow-sm overflow-hidden">
        <div class="p-6 border-b border-gray-200 dark:border-dark-border">
            <div class="flex items-center gap-3">
                <div class="p-2 bg-blue-100 dark:bg-blue-900/20 text-blue-600 rounded-lg">
                    <Icon icon="mdi:shield-check" class="w-6 h-6" />
                </div>
                <div>
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Network Core</h3>
                    <p class="text-sm text-gray-500">Manage core kernel networking features</p>
                </div>
            </div>
        </div>
        
        <div class="p-6 space-y-6">
            <div class="flex items-center justify-between">
                <div>
                    <p class="font-medium text-gray-900 dark:text-white">NAT Masquerade</p>
                    <p class="text-sm text-gray-500">Enable Network Address Translation for outgoing traffic</p>
                </div>
                <button 
                    onclick={toggleNAT}
                    aria-label="Toggle NAT Masquerade"
                    class={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${status.nat_enabled ? 'bg-primary-600' : 'bg-gray-200 dark:bg-gray-700'}`}
                >
                    <span class={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${status.nat_enabled ? 'translate-x-6' : 'translate-x-1'}`}></span>
                </button>
            </div>

            <div class="flex items-center justify-between">
                <div>
                    <p class="font-medium text-gray-900 dark:text-white">IP Forwarding</p>
                    <p class="text-sm text-gray-500">Allow packets to traverse through this host (net.ipv4.ip_forward)</p>
                </div>
                <button 
                    onclick={toggleForwarding}
                    aria-label="Toggle IP Forwarding"
                    class={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${status.forwarding_enabled ? 'bg-primary-600' : 'bg-gray-200 dark:bg-gray-700'}`}
                >
                    <span class={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${status.forwarding_enabled ? 'translate-x-6' : 'translate-x-1'}`}></span>
                </button>
            </div>
        </div>
    </div>

    <div class="bg-white dark:bg-dark-surface rounded-xl border border-gray-200 dark:border-dark-border shadow-sm overflow-hidden">
        <div class="p-6 border-b border-gray-200 dark:border-dark-border flex justify-between items-center">
            <div class="flex items-center gap-3">
                <div class="p-2 bg-green-100 dark:bg-green-900/20 text-green-600 rounded-lg">
                    <Icon icon="mdi:database" class="w-6 h-6" />
                </div>
                <div>
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Backup & Restore</h3>
                    <p class="text-sm text-gray-500">Manage configuration snapshots</p>
                </div>
            </div>
            <button 
                onclick={createBackup}
                class="flex items-center gap-2 px-4 py-2 bg-gray-900 dark:bg-white text-white dark:text-gray-900 rounded-lg hover:opacity-90 transition-opacity text-sm font-medium"
            >
                <Icon icon="mdi:content-save" class="w-4 h-4" />
                <span>Create Backup</span>
            </button>
        </div>

        <div class="divide-y divide-gray-200 dark:divide-dark-border">
            {#each backups as backup}
                <div class="p-4 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-dark-bg/50 transition-colors">
                    <div>
                        <p class="font-medium text-gray-900 dark:text-white">{backup.name || 'Auto Backup'}</p>
                        <p class="text-xs text-gray-500 font-mono">{new Date(backup.timestamp).toLocaleString()}</p>
                    </div>
                    <div class="flex items-center gap-2">
                        <a 
                            href={`/api/backup/export/${backup.timestamp}`}
                            class="p-2 text-gray-500 hover:text-primary-600 dark:hover:text-primary-400 transition-colors"
                            title="Download"
                        >
                            <Icon icon="mdi:download" class="w-4 h-4" />
                        </a>
                        <button 
                            onclick={() => restoreBackup(backup.timestamp)}
                            class="p-2 text-gray-500 hover:text-green-600 dark:hover:text-green-400 transition-colors"
                            title="Restore"
                        >
                            <Icon icon="mdi:upload" class="w-4 h-4" />
                        </button>
                    </div>
                </div>
            {/each}
            
            {#if backups.length === 0}
                <div class="p-8 text-center text-gray-500">No backups found.</div>
            {/if}
        </div>
    </div>

    <div class="text-center text-sm text-gray-400">
        NetNAT v{status.version}
    </div>
</div>
