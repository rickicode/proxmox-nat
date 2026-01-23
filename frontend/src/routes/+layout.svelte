<script>
    import '../app.css';
    import { onMount } from 'svelte';
    import Sidebar from '$lib/components/Sidebar.svelte';
    import Header from '$lib/components/Header.svelte';
    import Toast, { setToastInstance } from '$lib/components/Toast.svelte';
    import { appState } from '$lib/state.svelte.js';

    let { children } = $props();
    let toastComponent;

    onMount(() => {
        if (localStorage.theme === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            if (!appState.darkMode) appState.toggleTheme();
        } else {
            if (appState.darkMode) appState.toggleTheme();
        }

        // Set toast instance for global access
        if (toastComponent) {
            setToastInstance(toastComponent);
        }
    });
</script>

<div class="flex h-screen overflow-hidden bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-gray-100 font-sans">
    <Sidebar />

    <div class="relative flex flex-col flex-1 overflow-y-auto overflow-x-hidden">
        <Header />
        <main class="w-full flex-grow p-4 md:p-6 max-w-7xl mx-auto">
            {@render children()}
        </main>
    </div>
</div>

<Toast bind:this={toastComponent} />
