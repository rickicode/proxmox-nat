<script>
    import { api } from '$lib/api';
    import { onMount, onDestroy } from 'svelte';
    import Link from '$lib/components/Link.svelte';
    import { navigate } from '$lib/router.svelte.js';
    import Icon from '$lib/components/Icon.svelte';
    import EmptyState from '$lib/components/EmptyState.svelte';
    import SkeletonLoader from '$lib/components/SkeletonLoader.svelte';
    import TrafficChart from '$lib/components/TrafficChart.svelte';
    
    let stats = $state([
        { label: 'Uptime', value: '...', subtext: 'System up', icon: 'mdi:clock-outline', color: 'text-purple-500', bg: 'bg-purple-100 dark:bg-purple-900/20' },
        { label: 'CPU Load', value: '...', subtext: '1m / 5m / 15m', icon: 'mdi:cpu-64-bit', color: 'text-blue-500', bg: 'bg-blue-100 dark:bg-blue-900/20' },
        { label: 'Memory', value: '...', subtext: 'Used / Total', icon: 'mdi:memory', color: 'text-orange-500', bg: 'bg-orange-100 dark:bg-orange-900/20' },
        { label: 'Total Rules', value: '...', subtext: 'Active: ...', icon: 'mdi:shield-check', color: 'text-green-500', bg: 'bg-green-100 dark:bg-green-900/20' },
    ]);

    let rules = $state([]);
    let trafficHistory = $state(null);
    let loading = $state(true);
    let trafficLoading = $state(true);
    let statusInterval;
    let trafficInterval;

    async function loadSystemStatus() {
        try {
            const statusRes = await api.get('/status');
            if (statusRes.success) {
                stats[0].value = statusRes.data.uptime;
                stats[1].value = statusRes.data.cpu_load || 'N/A';
                stats[2].value = statusRes.data.memory_usage || 'N/A';
                stats[2].subtext = statusRes.data.memory_total ? `of ${statusRes.data.memory_total}` : 'Unknown total';
                stats[3].value = statusRes.data.rules_count || 0;
                stats[3].subtext = `Active: ${statusRes.data.active_rules || 0}`;
            }
        } catch (e) {
            console.error('Status load error:', e);
        }
    }

    async function loadRules() {
        try {
            const rulesRes = await api.get('/rules');
            if (rulesRes.success) {
                rules = rulesRes.data || [];
            }
        } catch (e) {
            console.error('Rules load error:', e);
        }
    }

    async function loadTraffic() {
        try {
            const res = await api.get('/network/traffic');
            if (res.success && res.data && res.data.total_traffic && res.data.total_traffic.daily_history) {
                trafficHistory = res.data.total_traffic.daily_history;
            }
        } catch (e) {
            console.error('Traffic load error:', e);
        } finally {
            trafficLoading = false;
        }
    }

    async function loadInitialData() {
        await Promise.all([
            loadSystemStatus(),
            loadTraffic(),
            loadRules()
        ]);
        loading = false;
    }

    onMount(() => {
        loadInitialData();
        
        // Refresh system status every 5 seconds
        statusInterval = setInterval(loadSystemStatus, 5000);
        
        // Refresh traffic every 30 seconds
        trafficInterval = setInterval(loadTraffic, 30000);
    });

    onDestroy(() => {
        if (statusInterval) clearInterval(statusInterval);
        if (trafficInterval) clearInterval(trafficInterval);
    });
</script>

<div class="space-y-6">
    <!-- Stats Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {#each stats as stat}
            <div class="bg-white dark:bg-dark-surface p-6 rounded-xl border border-gray-200 dark:border-dark-border shadow-sm hover:shadow-md transition-shadow">
                <div class="flex items-start justify-between mb-4">
                    <div class={`p-3 rounded-lg ${stat.bg} ${stat.color}`}>
                        <Icon icon={stat.icon} class="w-6 h-6" />
                    </div>
                </div>
                <div>
                    <h3 class="text-2xl font-bold text-gray-900 dark:text-white mb-1">{stat.value}</h3>
                    <p class="text-sm font-medium text-gray-900 dark:text-gray-300">{stat.label}</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">{stat.subtext}</p>
                </div>
            </div>
        {/each}
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Traffic Chart -->
        <div class="lg:col-span-2 bg-white dark:bg-dark-surface rounded-xl border border-gray-200 dark:border-dark-border shadow-sm p-6">
            <h3 class="font-semibold text-gray-900 dark:text-white mb-6 flex items-center gap-2">
                <Icon icon="mdi:chart-line" class="w-5 h-5 text-gray-500" />
                Network Traffic
            </h3>
            
            {#if trafficLoading}
                <div class="h-80 flex items-center justify-center">
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
                </div>
            {:else if trafficHistory}
                <TrafficChart history={trafficHistory} />
            {:else}
                <div class="h-80 flex flex-col items-center justify-center text-gray-500">
                    <Icon icon="mdi:chart-off" class="w-12 h-12 mb-2 opacity-50" />
                    <p>No traffic data available</p>
                    <p class="text-xs mt-1">Make sure vnstat is installed on the server</p>
                </div>
            {/if}
        </div>

        <!-- Recent Rules -->
        <div class="bg-white dark:bg-dark-surface rounded-xl border border-gray-200 dark:border-dark-border shadow-sm overflow-hidden flex flex-col">
            <div class="p-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center">
                <h3 class="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                    <Icon icon="mdi:shield-check" class="w-5 h-5 text-gray-500" />
                    Recent Rules
                </h3>
                <Link href="/rules" class="text-sm text-primary-600 hover:text-primary-700 font-medium flex items-center gap-1">
                    <span>View All</span>
                    <Icon icon="mdi:arrow-right" class="w-4 h-4" />
                </Link>
            </div>

            <div class="flex-1 overflow-y-auto min-h-[300px]">
                {#if loading}
                    <div class="p-4">
                        <SkeletonLoader rows={5} />
                    </div>
                {:else if rules.length === 0}
                    <div class="h-full flex flex-col items-center justify-center p-6 text-center">
                        <div class="p-4 bg-gray-50 dark:bg-dark-bg/50 rounded-full mb-3">
                            <Icon icon="mdi:network-off" class="w-8 h-8 text-gray-400" />
                        </div>
                        <h4 class="text-gray-900 dark:text-white font-medium mb-1">No rules found</h4>
                        <p class="text-sm text-gray-500 mb-4">Create your first NAT rule to start forwarding ports</p>
                        <button 
                            onclick={() => navigate('/rules')}
                            class="text-sm px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors"
                        >
                            Add Rule
                        </button>
                    </div>
                {:else}
                    <div class="divide-y divide-gray-200 dark:divide-dark-border">
                        {#each rules.slice(0, 5) as rule}
                            <div class="p-4 hover:bg-gray-50 dark:hover:bg-dark-bg/50 transition-colors">
                                <div class="flex items-center justify-between mb-2">
                                    <span class={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${rule.protocol === 'tcp' ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' : 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'}`}>
                                        {rule.protocol}
                                    </span>
                                    <div class={`w-2 h-2 rounded-full ${rule.enabled ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                                </div>
                                <p class="font-medium text-gray-900 dark:text-white text-sm truncate mb-1">{rule.name}</p>
                                <div class="flex items-center text-xs text-gray-500 font-mono gap-1">
                                    <span>:{rule.external_port}</span>
                                    <Icon icon="mdi:arrow-right" class="w-3 h-3" />
                                    <span class="truncate">{rule.internal_ip}:{rule.internal_port}</span>
                                </div>
                            </div>
                        {/each}
                    </div>
                {/if}
            </div>
        </div>
    </div>
</div>
