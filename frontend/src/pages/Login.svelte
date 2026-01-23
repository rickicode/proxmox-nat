<script>
	import { navigate } from '$lib/router.svelte.js';
	import { onMount } from 'svelte';
	import Icon from '$lib/components/Icon.svelte';
	import { toast } from '$lib/components/Toast.svelte';

	let username = $state('');
	let password = $state('');
	let rememberMe = $state(false);
	let loading = $state(false);

	onMount(() => {
		// Check if already logged in
		const token = localStorage.getItem('token');
		if (token) {
			navigate('/', { replace: true });
		}
	});

	async function handleLogin() {
		if (!username || !password) {
			toast('Please enter username and password', 'error');
			return;
		}

		loading = true;
		try {
			const response = await fetch('/api/login', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					username,
					password,
					remember_me: rememberMe
				})
			});

			const data = await response.json();

			if (data.success) {
				// Store token
				localStorage.setItem('token', data.data.token);
				localStorage.setItem('username', username);
				
				toast('Login successful!', 'success');
				navigate('/', { replace: true });
			} else {
				toast(data.error || 'Login failed', 'error');
			}
		} catch (error) {
			toast('Network error. Please try again.', 'error');
		} finally {
			loading = false;
		}
	}

	function handleKeyPress(event) {
		if (event.key === 'Enter') {
			handleLogin();
		}
	}
</script>

<div class="min-h-screen flex items-center justify-center p-4">
	<div class="w-full max-w-md">
		<!-- Logo & Title -->
		<div class="text-center mb-8">
			<div class="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-primary-500 to-primary-600 rounded-2xl mb-4 shadow-lg shadow-primary-500/30">
				<Icon icon="mdi:network-outline" class="w-10 h-10 text-white" />
			</div>
			<h1 class="text-3xl font-bold text-gray-900 dark:text-white mb-2 text-glow">NetNAT</h1>
			<p class="text-gray-600 dark:text-gray-300">Port Forwarding Manager</p>
		</div>

		<!-- Login Card -->
		<div class="glass rounded-2xl p-8">
			<h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-6">Sign In</h2>

			<div class="space-y-4">
				<!-- Username -->
				<div>
					<label for="username" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
						Username
					</label>
					<div class="relative">
						<Icon icon="mdi:account" class="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
						<input
							id="username"
							type="text"
							bind:value={username}
							onkeypress={handleKeyPress}
							placeholder="Enter your username"
							class="w-full pl-10 pr-4 py-3 bg-gray-50 dark:bg-dark-bg border border-gray-300 dark:border-dark-border rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:text-white transition-all"
							disabled={loading}
						/>
					</div>
				</div>

				<!-- Password -->
				<div>
					<label for="password" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
						Password
					</label>
					<div class="relative">
						<Icon icon="mdi:lock" class="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
						<input
							id="password"
							type="password"
							bind:value={password}
							onkeypress={handleKeyPress}
							placeholder="Enter your password"
							class="w-full pl-10 pr-4 py-3 bg-gray-50 dark:bg-dark-bg border border-gray-300 dark:border-dark-border rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:text-white transition-all"
							disabled={loading}
						/>
					</div>
				</div>

				<!-- Remember Me -->
				<div class="flex items-center">
					<input
						id="remember"
						type="checkbox"
						bind:checked={rememberMe}
						class="w-4 h-4 text-primary-600 bg-gray-100 border-gray-300 rounded focus:ring-primary-500 dark:bg-gray-700 dark:border-gray-600"
						disabled={loading}
					/>
					<label for="remember" class="ml-2 text-sm text-gray-600 dark:text-gray-400">
						Remember me for 30 days
					</label>
				</div>

				<!-- Login Button -->
				<button
					onclick={handleLogin}
					disabled={loading}
					class="w-full flex items-center justify-center gap-2 px-4 py-3 bg-primary-600 hover:bg-primary-700 text-white rounded-lg font-medium transition-colors shadow-lg shadow-primary-600/30 disabled:opacity-50 disabled:cursor-not-allowed"
				>
					{#if loading}
						<Icon icon="mdi:loading" class="w-5 h-5 animate-spin" />
						<span>Signing in...</span>
					{:else}
						<Icon icon="mdi:login" class="w-5 h-5" />
						<span>Sign In</span>
					{/if}
				</button>
			</div>

			<!-- Default Credentials Info -->
			<div class="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
				<div class="flex items-start gap-2">
					<Icon icon="mdi:information" class="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
					<div class="text-sm text-blue-800 dark:text-blue-300">
						<p class="font-medium mb-1">Default Credentials:</p>
						<p>Username: <code class="bg-blue-100 dark:bg-blue-900/40 px-1 rounded">admin</code></p>
						<p>Password: <code class="bg-blue-100 dark:bg-blue-900/40 px-1 rounded">netnat123</code></p>
					</div>
				</div>
			</div>
		</div>

		<!-- Footer -->
		<div class="text-center mt-6 text-sm text-gray-500 dark:text-gray-400">
			NetNAT v1.0.0 - Proxmox Port Forwarding Manager
		</div>
	</div>
</div>
