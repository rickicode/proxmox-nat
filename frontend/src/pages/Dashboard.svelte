<script>
    import { api } from '$lib/api';
    import { onMount } from 'svelte';
    import Link from '$lib/components/Link.svelte';
    import { navigate } from '$lib/router.svelte.js';
    import Icon from '$lib/components/Icon.svelte';
    import EmptyState from '$lib/components/EmptyState.svelte';
    import SkeletonLoader from '$lib/components/SkeletonLoader.svelte';
    
    let stats = $state([
        { label: 'Total Rules', value: '...', icon: 'mdi:shield-check', color: 'text-blue-500', bg: 'bg-blue-100 dark:bg-blue-900/20' },
        { label: 'Active Rules', value: '...', icon: 'mdi:check-network', color: 'text-green-500', bg: 'bg-green-100 dark:bg-green-900/20' },
        { label: 'Uptime', value: '...', icon: 'mdi:clock-outline', color: 'text-purple-500', bg: 'bg-purple-100 dark:bg-purple-900/20' },
    ]);

    let rules = $state([]);
    let loading = $state(true);

    async function loadDashboard() {
        try {
            const statusRes = await api.get('/status');
            if (statusRes.success) {
                stats[0].value = statusRes.data.rules_count || 0;
                stats[1].value = statusRes.data.active_rules || 0;
                stats[2].value = statusRes.data.uptime || 'N/A';
            }

            const rulesRes = await api.get('/rules');
            if (rulesRes.success) {
                rules = rulesRes.data || [];
            }
        } catch (e) {
            console.error('Dashboard load error:', e);
        } finally {
            loading = false;
        }
    }

    onMount(loadDashboard);
</script>

<div class="space-y-6">
    <!-- Stats Grid -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        {#each stats as stat}
            <div class="glass-panel p-6 rounded-xl flex items-center gap-4">
                <div class={`p-3 rounded-lg ${stat.bg} ${stat.color}`}>
                    <Icon icon={stat.icon} class="w-6 h-6" />
                </div>
                <div>
                    <p class="text-sm text-gray-600 dark:text-gray-300">{stat.label}</p>
                    <p class="text-2xl font-bold text-gray-900 dark:text-white">{stat.value}</p>
                </div>
            </div>
        {/each}
    </div>

    <!-- Recent Rules Preview -->
    <div class="glass rounded-xl overflow-hidden mt-6">
        <div class="p-4 border-b border-white/10 flex justify-between items-center">
            <h3 class="font-semibold text-gray-900 dark:text-white">Recent Rules</h3>
            <Link href="/rules" class="text-sm text-primary-600 hover:text-primary-700 font-medium flex items-center gap-1">
                <span>View All</span>
                <Icon icon="mdi:arrow-right" class="w-4 h-4" />
            </Link>
        </div>

        {#if loading}
            <div class="p-4">
                <SkeletonLoader rows={3} />
            </div>
        {:else if rules.length === 0}
            <EmptyState 
                icon="mdi:network-off"
                title="No rules configured"
                description="Create your first NAT rule to start managing port forwarding"
                actionText="Add First Rule"
                onAction={() => navigate('/rules')}
            />
        {:else}
            <div class="divide-y divide-gray-200 dark:divide-dark-border">
                {#each rules.slice(0, 5) as rule}
                    <div class="p-4 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-dark-bg/50 transition-colors">
                        <div class="flex items-center gap-3">
                            <span class={`px-2 py-1 rounded text-xs font-bold uppercase ${rule.protocol === 'tcp' ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' : 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'}`}>
                                {rule.protocol}
                            </span>
                            <div>
                                <p class="font-medium text-gray-900 dark:text-white text-sm">{rule.name}</p>
                                <p class="text-xs text-gray-500 font-mono">:{rule.external_port} → {rule.internal_ip}:{rule.internal_port}</p>
                            </div>
                        </div>
                        <div class={`w-2 h-2 rounded-full ${rule.enabled ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                    </div>
                {/each}
            </div>
        {/if}
    </div>
</div>
