<script>
    import { api } from '$lib/api';
    import { onMount } from 'svelte';
    import Icon from '$lib/components/Icon.svelte';
    import { toast } from '$lib/components/Toast.svelte';
    import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
    import EmptyState from '$lib/components/EmptyState.svelte';
    import SkeletonLoader from '$lib/components/SkeletonLoader.svelte';
    import { appState } from '$lib/state.svelte.js';

    let rules = $state([]);
    let discoveredVMs = $state([]);
    let loading = $state(true);
    let error = $state(null);
    let searchQuery = $state('');
    let filterProtocol = $state('all');
    let filterStatus = $state('all');
    let showModal = $state(false);
    let editingRule = $state(null);
    let confirmDialog = $state({ open: false, title: '', message: '', onConfirm: () => {} });
    let targetType = $state('ip'); // 'ip' or 'vm'

    let formData = $state({
        name: '',
        protocol: 'tcp',
        external_port: '',
        internal_ip: '',
        internal_port: '',
        target_vm_id: '',
        enabled: true
    });

    async function loadRules() {
        loading = true;
        try {
            const res = await api.get('/rules');
            if (res.success) {
                rules = res.data || [];
            }
        } catch (e) {
            error = e.message;
            toast(e.message, 'error');
        } finally {
            loading = false;
        }
    }

    async function handleSubmit() {
        try {
            const payload = {
                ...formData,
                external_port: parseInt(formData.external_port),
                internal_port: parseInt(formData.internal_port)
            };

            if (editingRule) {
                await api.put(`/rules/${editingRule.id}`, payload);
                toast('Rule updated successfully', 'success');
            } else {
                await api.post('/rules', payload);
                toast('Rule created successfully', 'success');
            }
            
            closeModal();
            loadRules();
        } catch (e) {
            toast(e.message, 'error');
        }
    }

    function confirmDelete(id, name) {
        confirmDialog = {
            open: true,
            title: 'Delete Rule',
            message: `Are you sure you want to delete "${name}"? This action cannot be undone.`,
            type: 'danger',
            confirmText: 'Delete',
            onConfirm: async () => {
                try {
                    await api.delete(`/rules/${id}`);
                    toast('Rule deleted successfully', 'success');
                    loadRules();
                } catch (e) {
                    toast(e.message, 'error');
                }
            }
        };
    }

    async function toggleRule(id) {
        try {
            await api.post(`/rules/${id}/toggle`);
            toast('Rule status updated', 'success');
            loadRules();
        } catch (e) {
            toast(e.message, 'error');
        }
    }

    async function loadVMs() {
        try {
            const res = await api.get('/vms');
            if (res.success) {
                discoveredVMs = res.data || [];
            }
        } catch (e) {
            console.error('Failed to load VMs:', e);
        }
    }

    function setTargetType(type) {
        targetType = type;
        if (type === 'vm' && discoveredVMs.length === 0) {
            loadVMs();
        }
    }

    function openModal(rule = null) {
        if (rule) {
            editingRule = rule;
            formData = { ...rule };
            targetType = rule.target_vm_id ? 'vm' : 'ip';
            if (targetType === 'vm') loadVMs();
        } else {
            editingRule = null;
            formData = {
                name: '',
                protocol: 'tcp',
                external_port: '',
                internal_ip: '',
                internal_port: '',
                target_vm_id: '',
                enabled: true
            };
            targetType = 'ip';
        }
        showModal = true;
    }

    function closeModal() {
        showModal = false;
        editingRule = null;
    }

    onMount(() => {
        loadRules();
        
        // Check for prefilled rule from discovery
        if (appState.prefillRule) {
            const prefill = appState.prefillRule;
            formData = {
                name: prefill.name,
                protocol: 'tcp',
                external_port: '',
                internal_ip: prefill.internal_ip,
                internal_port: '',
                target_vm_id: prefill.target_vm_id,
                enabled: true
            };
            targetType = 'vm';
            loadVMs(); // Load VMs to show correct name in dropdown
            showModal = true;
            appState.prefillRule = null; // Clear state
        }
    });

    let filteredRules = $derived(
        rules.filter(r => {
            const matchSearch = r.name?.toLowerCase().includes(searchQuery.toLowerCase()) || 
                               r.internal_ip?.includes(searchQuery) ||
                               r.external_port?.toString().includes(searchQuery);
            const matchProtocol = filterProtocol === 'all' || r.protocol === filterProtocol;
            const matchStatus = filterStatus === 'all' || 
                               (filterStatus === 'enabled' && r.enabled) ||
                               (filterStatus === 'disabled' && !r.enabled);
            return matchSearch && matchProtocol && matchStatus;
        })
    );
</script>

<div class="space-y-6">
    <div class="flex flex-col sm:flex-row justify-between gap-4 items-center">
        <h2 class="text-2xl font-bold text-gray-800 dark:text-white">NAT Rules</h2>
        <button 
            onclick={() => openModal()}
            class="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors shadow-lg shadow-primary-600/20"
        >
            <Icon icon="mdi:plus" class="w-4 h-4" />
            <span>Add New Rule</span>
        </button>
    </div>

    <!-- Search & Filters -->
    <div class="flex flex-col sm:flex-row gap-3">
        <div class="relative flex-1">
            <Icon icon="mdi:magnify" class="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input 
                type="text" 
                placeholder="Search by name, IP, or port..." 
                bind:value={searchQuery}
                class="w-full pl-10 pr-4 py-3 glass rounded-xl focus:outline-none focus:ring-2 focus:ring-primary-500/50 dark:text-white"
            />
        </div>
        
        <select 
            bind:value={filterProtocol}
            class="px-4 py-3 glass rounded-xl focus:outline-none focus:ring-2 focus:ring-primary-500/50 dark:text-white"
        >
            <option value="all">All Protocols</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="both">Both</option>
        </select>

        <select 
            bind:value={filterStatus}
            class="px-4 py-3 glass rounded-xl focus:outline-none focus:ring-2 focus:ring-primary-500/50 dark:text-white"
        >
            <option value="all">All Status</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
        </select>
    </div>

    {#if loading}
        <SkeletonLoader rows={5} />
    {:else if error}
        <div class="p-4 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 rounded-lg">
            {error}
        </div>
    {:else if filteredRules.length === 0}
        <div class="glass p-8 rounded-xl text-center">
            <EmptyState 
                icon={searchQuery || filterProtocol !== 'all' || filterStatus !== 'all' ? 'mdi:filter-off' : 'mdi:network-off'}
                title={searchQuery || filterProtocol !== 'all' || filterStatus !== 'all' ? 'No rules found' : 'No NAT rules yet'}
                description={searchQuery || filterProtocol !== 'all' || filterStatus !== 'all' ? 'Try adjusting your search or filters' : 'Create your first NAT rule to get started'}
                actionText={searchQuery || filterProtocol !== 'all' || filterStatus !== 'all' ? '' : 'Add First Rule'}
                onAction={() => openModal()}
            />
        </div>
    {:else}
        <div class="grid gap-4">
            {#each filteredRules as rule}
                <div class="glass-panel p-4 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
                        <div class="flex-1 space-y-2">
                            <div class="flex items-center gap-3">
                                <span class={`px-2 py-1 rounded text-xs font-bold uppercase ${rule.protocol === 'tcp' ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' : 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'}`}>
                                    {rule.protocol}
                                </span>
                                <h3 class="font-semibold text-gray-900 dark:text-white">{rule.name}</h3>
                                {#if !rule.enabled}
                                    <span class="px-2 py-0.5 rounded-full bg-gray-100 dark:bg-gray-700 text-gray-500 text-xs">Disabled</span>
                                {/if}
                            </div>
                            
                            <div class="flex items-center gap-3 text-sm font-mono text-gray-600 dark:text-gray-300">
                                <span class="bg-gray-50 dark:bg-dark-bg px-2 py-1 rounded">:{rule.external_port}</span>
                                <Icon icon="mdi:arrow-right" class="w-4 h-4 text-gray-400" />
                                <span class="bg-gray-50 dark:bg-dark-bg px-2 py-1 rounded">{rule.internal_ip}:{rule.internal_port}</span>
                            </div>
                        </div>

                        <div class="flex items-center gap-2 border-t md:border-t-0 pt-4 md:pt-0 border-gray-100 dark:border-dark-border">
                            <button 
                                onclick={() => toggleRule(rule.id)}
                                class={`p-2 rounded-lg transition-colors ${rule.enabled ? 'text-green-600 hover:bg-green-50 dark:text-green-400 dark:hover:bg-green-900/20' : 'text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'}`}
                                title={rule.enabled ? "Disable Rule" : "Enable Rule"}
                            >
                                <Icon icon="mdi:power" class="w-5 h-5" />
                            </button>
                            <button 
                                onclick={() => openModal(rule)}
                                class="p-2 text-blue-600 hover:bg-blue-50 dark:text-blue-400 dark:hover:bg-blue-900/20 rounded-lg transition-colors"
                                title="Edit Rule"
                            >
                                <Icon icon="mdi:pencil" class="w-5 h-5" />
                            </button>
                            <button 
                                onclick={() => confirmDelete(rule.id, rule.name)}
                                class="p-2 text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                                title="Delete Rule"
                            >
                                <Icon icon="mdi:trash-can-outline" class="w-5 h-5" />
                            </button>
                        </div>
                    </div>
                </div>
            {/each}
        </div>
    {/if}
</div>

<!-- Modal -->
{#if showModal}
    <div class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
        <div class="bg-white dark:bg-dark-surface w-full max-w-lg rounded-2xl shadow-2xl overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center">
                <h3 class="text-lg font-bold text-gray-900 dark:text-white">
                    {editingRule ? 'Edit Rule' : 'Add New Rule'}
                </h3>
                <button onclick={closeModal} class="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white">
                    <Icon icon="mdi:close" class="w-6 h-6" />
                </button>
            </div>
            
            <div class="p-6 space-y-4">
                <div>
                    <label for="rule-name" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Rule Name</label>
                    <input id="rule-name" type="text" bind:value={formData.name} class="w-full px-3 py-2 bg-gray-50 dark:bg-dark-bg border border-gray-300 dark:border-dark-border rounded-lg focus:ring-2 focus:ring-primary-500 dark:text-white" placeholder="e.g. Web Server" />
                </div>

                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label for="rule-protocol" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Protocol</label>
                        <select id="rule-protocol" bind:value={formData.protocol} class="w-full px-3 py-2 bg-gray-50 dark:bg-dark-bg border border-gray-300 dark:border-dark-border rounded-lg focus:ring-2 focus:ring-primary-500 dark:text-white">
                            <option value="tcp">TCP</option>
                            <option value="udp">UDP</option>
                            <option value="both">Both</option>
                        </select>
                    </div>
                    <div>
                        <label for="rule-ext-port" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">External Port</label>
                        <input id="rule-ext-port" type="number" bind:value={formData.external_port} class="w-full px-3 py-2 bg-gray-50 dark:bg-dark-bg border border-gray-300 dark:border-dark-border rounded-lg focus:ring-2 focus:ring-primary-500 dark:text-white" placeholder="8080" />
                    </div>
                </div>

                <!-- Target Type Selection -->
                <div class="space-y-3">
                    <span class="block text-sm font-medium text-gray-700 dark:text-gray-300">Target Type</span>
                    <div class="flex p-1 bg-gray-100 dark:bg-dark-bg rounded-lg">
                        <button 
                            class={`flex-1 py-1.5 text-sm font-medium rounded-md transition-all ${targetType === 'ip' ? 'bg-white dark:bg-dark-surface shadow text-gray-900 dark:text-white' : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'}`}
                            onclick={() => setTargetType('ip')}
                        >
                            Static IP
                        </button>
                        <button 
                            class={`flex-1 py-1.5 text-sm font-medium rounded-md transition-all ${targetType === 'vm' ? 'bg-white dark:bg-dark-surface shadow text-gray-900 dark:text-white' : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'}`}
                            onclick={() => setTargetType('vm')}
                        >
                            Dynamic VM
                        </button>
                    </div>
                </div>

                <div class="grid grid-cols-2 gap-4">
                    <div class="col-span-1">
                        {#if targetType === 'ip'}
                            <label for="rule-int-ip" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Internal IP</label>
                            <input id="rule-int-ip" type="text" bind:value={formData.internal_ip} class="w-full px-3 py-2 bg-gray-50 dark:bg-dark-bg border border-gray-300 dark:border-dark-border rounded-lg focus:ring-2 focus:ring-primary-500 dark:text-white" placeholder="10.0.0.x" />
                        {:else}
                            <label for="rule-vm-id" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Target VM</label>
                            <select id="rule-vm-id" bind:value={formData.target_vm_id} class="w-full px-3 py-2 bg-gray-50 dark:bg-dark-bg border border-gray-300 dark:border-dark-border rounded-lg focus:ring-2 focus:ring-primary-500 dark:text-white">
                                <option value="">Select a VM...</option>
                                {#each discoveredVMs as vm}
                                    <option value={vm.id}>{vm.id} - {vm.name} ({vm.ip || 'No IP'})</option>
                                {/each}
                            </select>
                            <p class="text-xs text-gray-500 mt-1">Rule will auto-update if VM IP changes</p>
                        {/if}
                    </div>
                    <div>
                        <label for="rule-int-port" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Internal Port</label>
                        <input id="rule-int-port" type="number" bind:value={formData.internal_port} class="w-full px-3 py-2 bg-gray-50 dark:bg-dark-bg border border-gray-300 dark:border-dark-border rounded-lg focus:ring-2 focus:ring-primary-500 dark:text-white" placeholder="80" />
                    </div>
                </div>

                <div class="flex items-center gap-2">
                    <input type="checkbox" id="enabled" bind:checked={formData.enabled} class="w-4 h-4 text-primary-600 rounded focus:ring-primary-500" />
                    <label for="enabled" class="text-sm font-medium text-gray-700 dark:text-gray-300">Enable this rule immediately</label>
                </div>
            </div>

            <div class="px-6 py-4 bg-gray-50 dark:bg-dark-bg/50 border-t border-gray-200 dark:border-dark-border flex justify-end gap-3">
                <button onclick={closeModal} class="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-border rounded-lg transition-colors">Cancel</button>
                <button onclick={handleSubmit} class="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors">
                    {editingRule ? 'Save Changes' : 'Create Rule'}
                </button>
            </div>
        </div>
    </div>
{/if}

<ConfirmDialog bind:open={confirmDialog.open} {...confirmDialog} />
