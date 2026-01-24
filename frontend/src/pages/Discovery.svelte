<script>
    import { api } from '$lib/api';
    import { onMount } from 'svelte';
    import { fly, fade } from 'svelte/transition';
    import { quintOut } from 'svelte/easing';
    import Icon from '$lib/components/Icon.svelte';
    import { appState } from '$lib/state.svelte.js';
    import { navigate } from '$lib/router.svelte.js';
    import { toast } from '$lib/components/Toast.svelte';

    let vms = $state([]);
    let loading = $state(true);
    let refreshing = $state(false);
    let searchQuery = $state('');
    
    // Filters
    let filterType = $state('all'); // 'all', 'qemu', 'lxc'
    let filterStatus = $state('all'); // 'all', 'running', 'stopped'
    let filterNode = $state('all'); // 'all', 'pve', etc.

    async function loadVMs() {
        loading = true;
        try {
            const res = await api.get('/vms');
            if (res.success) {
                vms = res.data || [];
            }
        } catch (e) {
            console.error(e);
            toast('Failed to load VMs', 'error');
        } finally {
            loading = false;
        }
    }

    async function refreshDiscovery() {
        refreshing = true;
        try {
            const res = await api.post('/vms/refresh');
            if (res.success) {
                toast('Scanning for VMs...', 'info');
                setTimeout(loadVMs, 2000); 
            }
        } catch (e) {
            console.error('Failed to trigger refresh:', e);
            toast('Failed to start scan', 'error');
        } finally {
            refreshing = false;
        }
    }

    function handlePortForward(vm) {
        appState.prefillRule = {
            target_type: 'vm',
            target_vm_id: vm.id,
            internal_ip: vm.ip,
            name: `${vm.name} Rule`
        };
        navigate('/rules');
    }

    function copyToClipboard(text, label) {
        if (!text) return;
        navigator.clipboard.writeText(text);
        toast(`${label} copied to clipboard`, 'success');
    }

    onMount(loadVMs);

    let filteredVMs = $derived(
        vms.filter(vm => {
            const matchesSearch = vm.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
                                  vm.id.toString().includes(searchQuery) ||
                                  (vm.ip && vm.ip.includes(searchQuery));
            
            const matchesType = filterType === 'all' || vm.type === filterType;
            
            const matchesStatus = filterStatus === 'all' || 
                                  (filterStatus === 'running' && vm.status === 'running') ||
                                  (filterStatus === 'stopped' && vm.status !== 'running');

            const matchesNode = filterNode === 'all' || vm.node === filterNode;

            return matchesSearch && matchesType && matchesStatus && matchesNode;
        })
    );

    let typeCount = $derived({
        all: vms.length,
        qemu: vms.filter(v => v.type === 'qemu').length,
        lxc: vms.filter(v => v.type === 'lxc').length
    });

    let uniqueNodes = $derived(
        Array.from(new Set(vms.map(v => v.node))).filter(Boolean).sort()
    );
</script>

<div class="space-y-6">
    <!-- Header Section -->
    <div class="flex flex-col md:flex-row justify-between gap-6 items-start md:items-center">
        <div>
            <h2 class="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-gray-900 to-gray-600 dark:from-white dark:to-gray-400">
                Discovery
            </h2>
            <div class="flex items-center gap-2 mt-1">
                <span class="text-gray-500 dark:text-gray-400 text-sm">Detected Resources</span>
                <span class="px-2 py-0.5 rounded-full bg-gray-100 dark:bg-dark-surface border border-gray-200 dark:border-dark-border text-xs font-medium text-gray-600 dark:text-gray-300">
                    {vms.length} Total
                </span>
            </div>
        </div>
        
        <div class="flex items-center gap-3">
             <button 
                onclick={refreshDiscovery}
                disabled={refreshing}
                class="group relative flex items-center gap-2 px-5 py-2.5 bg-primary-600 hover:bg-primary-700 text-white rounded-xl shadow-lg shadow-primary-600/20 transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-70 disabled:hover:scale-100 overflow-hidden"
            >
                <div class="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300"></div>
                <Icon icon="mdi:refresh" class={`w-5 h-5 ${refreshing ? 'animate-spin' : ''}`} />
                <span class="font-medium relative">{refreshing ? 'Scanning Network...' : 'Scan Network'}</span>
            </button>
        </div>
    </div>

    <!-- Toolbar -->
    <div class="glass p-2 rounded-2xl flex flex-col md:flex-row gap-2">
        <div class="relative flex-1">
            <Icon icon="mdi:magnify" class="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input 
                type="text" 
                placeholder="Search by Name, ID, or IP..." 
                bind:value={searchQuery}
                class="w-full pl-11 pr-4 py-2.5 bg-gray-50/50 dark:bg-dark-bg/50 border-none rounded-xl text-sm focus:ring-2 focus:ring-primary-500/50 transition-all"
            />
        </div>
        
        <div class="flex gap-2 overflow-x-auto pb-1 md:pb-0">
            <!-- Type Filters -->
            <div class="flex p-1 bg-gray-100 dark:bg-dark-bg rounded-xl">
                <button 
                    onclick={() => filterType = 'all'}
                    class={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all ${filterType === 'all' ? 'bg-white dark:bg-dark-surface shadow text-gray-900 dark:text-white' : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'}`}
                >
                    All
                </button>
                <button 
                    onclick={() => filterType = 'qemu'}
                    class={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${filterType === 'qemu' ? 'bg-white dark:bg-dark-surface shadow text-gray-900 dark:text-white' : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'}`}
                >
                    <Icon icon="mdi:monitor" class="w-4 h-4" />
                    <span>VMs</span>
                </button>
                <button 
                    onclick={() => filterType = 'lxc'}
                    class={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${filterType === 'lxc' ? 'bg-white dark:bg-dark-surface shadow text-gray-900 dark:text-white' : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'}`}
                >
                    <Icon icon="mdi:cube-outline" class="w-4 h-4" />
                    <span>LXC</span>
                </button>
            </div>

            <!-- Node Filter -->
            {#if uniqueNodes.length > 0}
                <select 
                    bind:value={filterNode}
                    class="px-4 py-2 bg-gray-100 dark:bg-dark-bg border-none rounded-xl text-sm font-medium text-gray-700 dark:text-gray-300 focus:ring-2 focus:ring-primary-500/50 cursor-pointer min-w-[120px]"
                >
                    <option value="all">All Nodes</option>
                    {#each uniqueNodes as node}
                        <option value={node}>{node}</option>
                    {/each}
                </select>
            {/if}

            <!-- Status Filter -->
            <select 
                bind:value={filterStatus}
                class="px-4 py-2 bg-gray-100 dark:bg-dark-bg border-none rounded-xl text-sm font-medium text-gray-700 dark:text-gray-300 focus:ring-2 focus:ring-primary-500/50 cursor-pointer min-w-[120px]"
            >
                <option value="all">All Status</option>
                <option value="running">Running</option>
                <option value="stopped">Stopped</option>
            </select>
        </div>
    </div>

    <!-- Grid -->
    {#if loading}
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
            {#each Array(6) as _}
                <div class="h-64 bg-gray-100 dark:bg-dark-surface rounded-2xl animate-pulse ring-1 ring-black/5 dark:ring-white/5"></div>
            {/each}
        </div>
    {:else}
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
            {#each filteredVMs as vm, i (vm.id)}
                <div 
                    in:fly={{ y: 20, duration: 400, delay: i * 50, easing: quintOut }}
                    class="group relative bg-white dark:bg-dark-surface rounded-2xl ring-1 ring-gray-200 dark:ring-dark-border p-5 hover:shadow-xl hover:shadow-primary-500/5 dark:hover:shadow-primary-500/10 hover:-translate-y-1 transition-all duration-300 overflow-hidden"
                >
                    <!-- Glossy Effect -->
                    <div class="absolute inset-0 bg-gradient-to-br from-white/50 to-transparent dark:from-white/5 dark:to-transparent pointer-events-none"></div>

                    <!-- Header -->
                    <div class="relative z-10 flex justify-between items-start mb-6">
                        <div class="flex gap-4">
                            <div class={`w-12 h-12 rounded-2xl flex items-center justify-center shadow-inner ${vm.type === 'lxc' ? 'bg-purple-50 text-purple-600 dark:bg-purple-900/20 dark:text-purple-400' : 'bg-blue-50 text-blue-600 dark:bg-blue-900/20 dark:text-blue-400'}`}>
                                <Icon icon={vm.type === 'lxc' ? 'mdi:cube-outline' : 'mdi:monitor'} class="w-7 h-7" />
                            </div>
                            <div>
                                <h3 class="font-bold text-gray-900 dark:text-white text-lg leading-tight mb-1 group-hover:text-primary-600 dark:group-hover:text-primary-400 transition-colors">
                                    {vm.name}
                                </h3>
                                <div class="flex items-center gap-2">
                                    <button 
                                        onclick={() => copyToClipboard(vm.id, 'VM ID')}
                                        class="text-xs font-mono text-gray-500 hover:text-primary-600 dark:text-gray-400 dark:hover:text-primary-400 transition-colors flex items-center gap-1"
                                        title="Copy ID"
                                    >
                                        #{vm.id}
                                        <Icon icon="mdi:content-copy" class="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                                    </button>
                                    <span class="w-1 h-1 rounded-full bg-gray-300 dark:bg-gray-600"></span>
                                    <span class="text-xs font-medium uppercase text-gray-500 dark:text-gray-400">{vm.type}</span>
                                    {#if vm.node}
                                        <span class="w-1 h-1 rounded-full bg-gray-300 dark:bg-gray-600"></span>
                                        <span class="text-xs font-medium text-gray-500 dark:text-gray-400">Node: {vm.node}</span>
                                    {/if}
                                </div>
                            </div>
                        </div>
                        
                        <div class={`px-2.5 py-1 rounded-lg text-xs font-bold uppercase tracking-wide border ${vm.status === 'running' ? 'bg-green-50 text-green-700 border-green-200 dark:bg-green-900/20 dark:text-green-400 dark:border-green-900/50' : 'bg-gray-50 text-gray-600 border-gray-200 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-700'}`}>
                            {vm.status}
                        </div>
                    </div>

                    <!-- Network Info -->
                    <div class="relative z-10 bg-gray-50 dark:bg-black/20 rounded-xl p-4 mb-6 border border-gray-100 dark:border-white/5 group-hover:border-primary-100 dark:group-hover:border-primary-900/30 transition-colors">
                        <div class="flex justify-between items-center mb-2">
                            <span class="text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</span>
                            <span class="text-xs text-gray-400 flex items-center gap-1">
                                <Icon icon="mdi:lan" class="w-3 h-3" />
                                {vm.source === 'agent' ? 'Guest Agent' : vm.source === 'arp' ? 'ARP Discovery' : 'Config'}
                            </span>
                        </div>
                        <div class="flex items-center justify-between">
                            {#if vm.ip}
                                <span class="font-mono text-sm font-semibold text-gray-900 dark:text-white select-all">
                                    {vm.ip}
                                </span>
                                <button 
                                    onclick={() => copyToClipboard(vm.ip, 'IP Address')}
                                    class="p-1.5 text-gray-400 hover:text-primary-600 dark:hover:text-primary-400 hover:bg-white dark:hover:bg-dark-surface rounded-lg transition-all"
                                    title="Copy IP"
                                >
                                    <Icon icon="mdi:content-copy" class="w-4 h-4" />
                                </button>
                            {:else}
                                <span class="text-sm text-gray-400 italic">Not Detected</span>
                            {/if}
                        </div>
                    </div>

                    <!-- Actions -->
                    <div class="relative z-10">
                        <button 
                            onclick={() => handlePortForward(vm)}
                            class="w-full py-3 rounded-xl font-medium text-sm flex items-center justify-center gap-2 transition-all duration-300
                            {vm.ip 
                                ? 'bg-gray-900 text-white hover:bg-primary-600 shadow-lg hover:shadow-primary-600/30 dark:bg-white dark:text-black dark:hover:bg-primary-400' 
                                : 'bg-gray-100 text-gray-400 cursor-not-allowed dark:bg-dark-border dark:text-gray-500'}"
                            disabled={!vm.ip}
                        >
                            {#if vm.ip}
                                <Icon icon="mdi:flash" class="w-4 h-4 text-yellow-400 dark:text-yellow-600" />
                                <span>Forward Port</span>
                            {:else}
                                <Icon icon="mdi:close-circle-outline" class="w-4 h-4" />
                                <span>No IP Available</span>
                            {/if}
                        </button>
                    </div>
                </div>
            {/each}

            {#if filteredVMs.length === 0}
                <div class="col-span-full py-20">
                    <div class="max-w-md mx-auto text-center space-y-4">
                        <div class="w-20 h-20 bg-gray-100 dark:bg-dark-surface rounded-3xl mx-auto flex items-center justify-center">
                            <Icon icon={searchQuery ? 'mdi:filter-remove' : 'mdi:server-network-off'} class="w-10 h-10 text-gray-400" />
                        </div>
                        <h3 class="text-xl font-bold text-gray-900 dark:text-white">No Resources Found</h3>
                        <p class="text-gray-500 dark:text-gray-400">
                            {searchQuery || filterType !== 'all' || filterStatus !== 'all' || filterNode !== 'all'
                                ? 'Adjust your filters or search terms to find what you\'re looking for.' 
                                : 'Scan your network to detect running VMs and LXC containers.'}
                        </p>
                        {#if searchQuery || filterType !== 'all' || filterStatus !== 'all' || filterNode !== 'all'}
                            <button 
                                onclick={() => { searchQuery = ''; filterType = 'all'; filterStatus = 'all'; filterNode = 'all'; }}
                                class="text-primary-600 hover:text-primary-700 font-medium hover:underline"
                            >
                                Clear all filters
                            </button>
                        {/if}
                    </div>
                </div>
            {/if}
        </div>
    {/if}
</div>
