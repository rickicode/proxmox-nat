<script>
    import { appState } from '$lib/state.svelte.js';
    import Icon from '$lib/components/Icon.svelte';
    import { page } from '$app/stores';

    let navigation = [
        { name: 'Dashboard', href: '/', icon: 'mdi:view-dashboard' },
        { name: 'NAT Rules', href: '/rules', icon: 'mdi:network' },
        { name: 'Discovery', href: '/discovery', icon: 'mdi:server-network' },
        { name: 'Settings', href: '/settings', icon: 'mdi:cog' },
    ];

    let currentPath = $derived($page.url.pathname);
</script>

<!-- Mobile Backdrop -->
{#if appState.sidebarOpen}
    <div 
        class="fixed inset-0 z-20 bg-black/50 lg:hidden"
        onclick={() => appState.setSidebar(false)}
        role="button"
        tabindex="0"
        onkeydown={(e) => e.key === 'Enter' && appState.setSidebar(false)}
    ></div>
{/if}

<aside 
    class={`
        fixed inset-y-0 left-0 z-30 w-64 transform bg-white dark:bg-dark-surface border-r border-gray-200 dark:border-dark-border transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0
        ${appState.sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
    `}
>
    <div class="flex items-center justify-between h-16 px-6 border-b border-gray-200 dark:border-dark-border">
        <div class="flex items-center gap-2 font-bold text-xl text-primary-600 dark:text-primary-500">
            <Icon icon="mdi:network-outline" class="w-8 h-8" />
            <span>NetNAT</span>
        </div>
        <button 
            class="lg:hidden text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
            onclick={() => appState.setSidebar(false)}
        >
            <Icon icon="mdi:close" class="w-6 h-6" />
        </button>
    </div>

    <nav class="flex flex-col gap-1 p-4">
        {#each navigation as item}
            <a 
                href={item.href}
                class={`
                    flex items-center gap-3 px-4 py-3 rounded-lg transition-colors
                    ${currentPath === item.href 
                        ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-400' 
                        : 'text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-dark-bg'}
                `}
            >
                <Icon icon={item.icon} class="w-5 h-5" />
                <span class="font-medium">{item.name}</span>
            </a>
        {/each}
    </nav>

    <div class="absolute bottom-0 w-full p-4 border-t border-gray-200 dark:border-dark-border">
        <button class="flex items-center gap-3 px-4 py-3 w-full text-left rounded-lg text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20 transition-colors">
            <Icon icon="mdi:logout" class="w-5 h-5" />
            <span class="font-medium">Logout</span>
        </button>
    </div>
</aside>
