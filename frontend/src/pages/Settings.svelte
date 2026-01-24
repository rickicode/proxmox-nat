<script>
    import { api } from '$lib/api';
    import { onMount } from 'svelte';
    import Icon from '$lib/components/Icon.svelte';
    import { toast } from '$lib/components/Toast.svelte';

    let status = $state({
        nat_enabled: false,
        forwarding_enabled: false,
        version: ''
    });

    let backups = $state([]);
    let loading = $state(false);

    let configContent = $state('');
    let saving = $state(false);

    async function loadData() {
        try {
            // Load system status & version
            const statusRes = await api.get('/status');
            if (statusRes.success) {
                status = { ...status, ...statusRes.data };
            }
            const ver = await api.get('/version');
            if (ver.success) {
                status.version = ver.data.version;
            }

            // Load config
            const configRes = await api.get('/config');
            if (configRes.success) {
                configContent = configRes.data;
            }

            loadBackups();
        } catch (e) {
            console.error(e);
            toast('Failed to load settings', 'error');
        }
    }

    async function saveConfig() {
        saving = true;
        try {
            const res = await api.put('/config', { content: configContent });
            toast(res.message || 'Configuration saved', 'success');
        } catch (e) {
            toast(e.message || 'Failed to save configuration', 'error');
        } finally {
            saving = false;
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

    async function createBackup() {
        const name = prompt('Enter backup name (optional):');
        if (name === null) return;
        
        try {
            await api.post('/backup/create', { name });
            loadBackups();
            toast('Backup created successfully', 'success');
        } catch (e) {
            toast(e.message, 'error');
        }
    }

    async function restoreBackup(path) {
        if (!confirm('Are you sure? This will overwrite current rules.')) return;
        try {
            await api.post('/backup/restore', { backup_path: path, preview: false });
            toast('Backup restored successfully', 'success');
        } catch (e) {
            toast(e.message, 'error');
        }
    }

    onMount(loadData);
</script>

<div class="space-y-6">
    <div class="flex flex-col sm:flex-row justify-between gap-4 items-center">
        <div>
            <h2 class="text-2xl font-bold text-gray-800 dark:text-white">System Settings</h2>
            <p class="text-gray-500 dark:text-gray-400 text-sm">Manage core configuration, backups, and system status</p>
        </div>
    </div>

    <!-- Configuration Editor -->
    <div class="glass rounded-xl overflow-hidden">
        <div class="p-6 border-b border-white/10">
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <div class="p-2 bg-purple-100 dark:bg-purple-900/20 text-purple-600 rounded-lg">
                        <Icon icon="mdi:file-document-edit" class="w-6 h-6" />
                    </div>
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Configuration Editor</h3>
                        <p class="text-sm text-gray-600 dark:text-gray-400">Edit server configuration (config.yml)</p>
                    </div>
                </div>
                <button 
                    onclick={saveConfig}
                    disabled={saving}
                    class="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors disabled:opacity-50 shadow-lg shadow-primary-600/20"
                >
                    {#if saving}
                        <Icon icon="mdi:loading" class="w-4 h-4 animate-spin" />
                        <span>Saving...</span>
                    {:else}
                        <Icon icon="mdi:content-save" class="w-4 h-4" />
                        <span>Save Changes</span>
                    {/if}
                </button>
            </div>
        </div>
        
        <div class="p-0">
            <textarea 
                bind:value={configContent}
                class="w-full h-[500px] p-4 font-mono text-sm bg-gray-50 dark:bg-dark-bg text-gray-800 dark:text-gray-200 focus:outline-none resize-y"
                spellcheck="false"
            ></textarea>
        </div>
        <div class="px-6 py-3 bg-yellow-50 dark:bg-yellow-900/10 border-t border-yellow-100 dark:border-yellow-900/20 text-xs text-yellow-700 dark:text-yellow-400 flex items-center gap-2">
            <Icon icon="mdi:alert" class="w-4 h-4" />
            <span>Warning: Incorrect configuration may disrupt service. Some changes require a server restart to take effect.</span>
        </div>
    </div>

    <div class="glass rounded-xl overflow-hidden">
        <div class="p-6 border-b border-white/10 flex justify-between items-center">
            <div class="flex items-center gap-3">
                <div class="p-2 bg-green-100 dark:bg-green-900/20 text-green-600 rounded-lg">
                    <Icon icon="mdi:database" class="w-6 h-6" />
                </div>
                <div>
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Backup & Restore</h3>
                    <p class="text-sm text-gray-600 dark:text-gray-400">Manage configuration snapshots</p>
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

        <div class="divide-y divide-gray-200/50 dark:divide-white/5">
            {#each backups as backup}
                <div class="p-4 flex items-center justify-between hover:bg-black/5 dark:hover:bg-white/5 transition-colors">
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
