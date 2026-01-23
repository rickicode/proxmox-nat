<script>
    import { onMount } from 'svelte';
    import { router, navigate } from '$lib/router.svelte.js';
    import Sidebar from '$lib/components/Sidebar.svelte';
    import Header from '$lib/components/Header.svelte';
    import { appState } from '$lib/state.svelte.js';

    // Page Title Management
    const pageTitles = {
        '/': 'Dashboard',
        '/login': 'Sign In',
        '/rules': 'NAT Rules',
        '/discovery': 'VM Discovery',
        '/settings': 'Settings'
    };

    $effect(() => {
        const title = pageTitles[router.path] || 'NetNAT';
        document.title = `${title} - NetNAT`;
    });

    // Pages
    import Dashboard from './pages/Dashboard.svelte';
    import Login from './pages/Login.svelte';
    import Rules from './pages/Rules.svelte';
    import Discovery from './pages/Discovery.svelte';
    import Settings from './pages/Settings.svelte';
    
    // Reactive check for login page
    let isLoginPage = $derived(router.path === '/login');

    // Auth Protection
    $effect(() => {
        const token = localStorage.getItem('token');
        const path = router.path;
        
        if (!token && path !== '/login') {
            navigate('/login', { replace: true });
        } else if (token && path === '/login') {
            navigate('/', { replace: true });
        }
    });

    onMount(() => {
        // Theme initialization
        if (localStorage.theme === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            if (!appState.darkMode) appState.toggleTheme();
        } else {
            if (appState.darkMode) appState.toggleTheme();
        }
    });
    
    // Determine which page to show
    let CurrentPage = $derived({
        '/': Dashboard,
        '/rules': Rules,
        '/discovery': Discovery,
        '/settings': Settings
    }[router.path] || Dashboard);
</script>

{#if isLoginPage}
    <Login />
{:else}
    <!-- Main Layout -->
    <div class="flex h-screen overflow-hidden font-sans">
        <Sidebar />

        <div class="relative flex flex-col flex-1 overflow-y-auto overflow-x-hidden">
            <Header />
            <main class="w-full flex-grow p-4 md:p-6 max-w-7xl mx-auto z-10">
                <CurrentPage />
            </main>
        </div>
    </div>
{/if}
