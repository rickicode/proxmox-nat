<script>
	import '../app.css';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import Header from '$lib/components/Header.svelte';
	import Toast, { setToastInstance } from '$lib/components/Toast.svelte';
	import { appState } from '$lib/state.svelte.js';

	let { children } = $props();
	let toastComponent;

	onMount(() => {
		// Theme initialization
		if (localStorage.theme === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
			if (!appState.darkMode) appState.toggleTheme();
		} else {
			if (appState.darkMode) appState.toggleTheme();
		}

		// Set toast instance for global access
		if (toastComponent) {
			setToastInstance(toastComponent);
		}

		// Auth check - redirect to login if not authenticated
		const currentPath = $page.url.pathname;
		const token = localStorage.getItem('token');
		
		if (!token && currentPath !== '/login') {
			goto('/login');
		} else if (token && currentPath === '/login') {
			goto('/');
		}
	});
</script>

{#if $page.url.pathname === '/login'}
	<!-- Login page - no layout -->
	{@render children()}
{:else}
	<!-- Main app layout -->
	<div class="flex h-screen overflow-hidden bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-gray-100 font-sans">
		<Sidebar />

		<div class="relative flex flex-col flex-1 overflow-y-auto overflow-x-hidden">
			<Header />
			<main class="w-full flex-grow p-4 md:p-6 max-w-7xl mx-auto">
				{@render children()}
			</main>
		</div>
	</div>
{/if}

<Toast bind:this={toastComponent} />
