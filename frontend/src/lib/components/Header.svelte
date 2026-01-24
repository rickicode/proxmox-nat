<script>
    import { appState } from '$lib/state.svelte.js';
    import Icon from '$lib/components/Icon.svelte';
    import { router } from '$lib/router.svelte.js';

    let pageTitles = {
        '/': 'Dashboard',
        '/rules': 'NAT Rules',
        '/discovery': 'VM Discovery',
        '/settings': 'System Settings'
    };

    let currentTitle = $derived(pageTitles[router.path] || 'Dashboard');
</script>

<header class="sticky top-0 z-10 flex items-center justify-between h-16 min-h-[4rem] px-4 glass my-4 mx-4 md:mx-6 rounded-2xl shrink-0">
    <div class="flex items-center gap-4">
        <button 
            class="p-2 -ml-2 text-gray-600 rounded-lg lg:hidden hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-dark-bg"
            onclick={() => appState.toggleSidebar()}
        >
            <Icon icon="mdi:menu" class="w-6 h-6" />
        </button>
        <h1 class="text-lg font-semibold text-gray-800 dark:text-white hidden sm:block">{currentTitle}</h1>
    </div>

    <div class="flex items-center gap-2 sm:gap-4">
        <button 
            class="p-2 text-gray-500 rounded-lg hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-dark-bg transition-colors"
            onclick={() => appState.toggleTheme()}
            aria-label="Toggle Theme"
        >
            {#if appState.darkMode}
                <Icon icon="mdi:white-balance-sunny" class="w-5 h-5" />
            {:else}
                <Icon icon="mdi:moon-waning-crescent" class="w-5 h-5" />
            {/if}
        </button>



        <div class="h-8 w-px bg-gray-200 dark:bg-dark-border mx-1"></div>

        <div class="flex items-center gap-3">
            <div class="hidden md:block text-right">
                <p class="text-sm font-medium text-gray-900 dark:text-white">Admin User</p>
                <p class="text-xs text-gray-500 dark:text-gray-400">Administrator</p>
            </div>
            <div class="w-8 h-8 rounded-full bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center text-primary-600 dark:text-primary-400">
                <Icon icon="mdi:account" class="w-5 h-5" />
            </div>
        </div>
    </div>
</header>
