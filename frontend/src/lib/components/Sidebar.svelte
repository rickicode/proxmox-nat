<script>
    import { appState } from '$lib/state.svelte.js';
    import Icon from '$lib/components/Icon.svelte';
    import Link from '$lib/components/Link.svelte';
    import { router, navigate } from '$lib/router.svelte.js';
    import { toast } from '$lib/components/Toast.svelte';

    let navigation = [
        { name: 'Dashboard', href: '/', icon: 'mdi:view-dashboard' },
        { name: 'NAT Rules', href: '/rules', icon: 'mdi:network' },
        { name: 'Discovery', href: '/discovery', icon: 'mdi:server-network' },
        { name: 'Settings', href: '/settings', icon: 'mdi:cog' },
    ];

    let currentPath = $derived(router.path);

    function handleLogout() {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        toast('Logged out successfully', 'success');
        navigate('/login');
    }
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
        fixed inset-y-4 left-4 z-30 w-64 transform glass rounded-2xl transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0 lg:m-4 lg:mr-0
        ${appState.sidebarOpen ? 'translate-x-0' : '-translate-x-[120%]'}
    `}
>
    <div class="flex items-center justify-between h-16 px-6 border-b border-white/10">
        <div class="flex items-center gap-3 font-bold text-xl text-gray-900 dark:text-white">
            <img src="/logo.svg" alt="NetNAT" class="w-10 h-10" />
            <span class="tracking-tight">NetNAT</span>
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
            <Link 
                href={item.href}
                onclick={() => appState.setSidebar(false)}
                class={`
                    flex items-center gap-3 px-4 py-3 rounded-lg transition-colors
                    ${currentPath === item.href 
                        ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-400' 
                        : 'text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-dark-bg'}
                `}
            >
                <Icon icon={item.icon} class="w-5 h-5" />
                <span class="font-medium">{item.name}</span>
            </Link>
        {/each}
    </nav>

    <div class="absolute bottom-0 w-full p-4 border-t border-white/10">
        <button 
            onclick={handleLogout}
            class="flex items-center gap-3 px-4 py-3 w-full text-left rounded-lg text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20 transition-colors"
        >
            <Icon icon="mdi:logout" class="w-5 h-5" />
            <span class="font-medium">Logout</span>
        </button>
    </div>
</aside>
