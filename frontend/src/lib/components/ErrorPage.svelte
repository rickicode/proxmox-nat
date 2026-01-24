<script>
    import Icon from '$lib/components/Icon.svelte';
    import { navigate } from '$lib/router.svelte.js';

    export let error = {
        code: 404,
        title: 'Page Not Found',
        message: 'The page you are looking for does not exist.',
        icon: 'mdi:alert-circle-outline'
    };

    function goHome() {
        navigate('/');
    }

    function goBack() {
        window.history.back();
    }
</script>

<div class="min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full text-center space-y-6">
        <!-- Error Icon -->
        <div class="inline-flex items-center justify-center w-24 h-24 bg-gradient-to-br from-red-500 to-red-600 rounded-3xl shadow-lg shadow-red-500/30 mb-4">
            <Icon icon={error.icon} class="w-14 h-14 text-white" />
        </div>

        <!-- Error Code -->
        <div>
            <h1 class="text-8xl font-bold text-gray-900 dark:text-white mb-2">
                {error.code}
            </h1>
            <h2 class="text-2xl font-bold text-gray-800 dark:text-gray-200 mb-3">
                {error.title}
            </h2>
            <p class="text-gray-600 dark:text-gray-400">
                {error.message}
            </p>
        </div>

        <!-- Actions -->
        <div class="flex gap-3 justify-center pt-4">
            <button
                onclick={goBack}
                class="px-6 py-3 bg-gray-100 hover:bg-gray-200 dark:bg-dark-surface dark:hover:bg-dark-border text-gray-700 dark:text-gray-300 rounded-xl font-medium transition-colors flex items-center gap-2"
            >
                <Icon icon="mdi:arrow-left" class="w-5 h-5" />
                Go Back
            </button>
            <button
                onclick={goHome}
                class="px-6 py-3 bg-primary-600 hover:bg-primary-700 text-white rounded-xl font-medium transition-colors shadow-lg shadow-primary-600/30 flex items-center gap-2"
            >
                <Icon icon="mdi:home" class="w-5 h-5" />
                Go Home
            </button>
        </div>

        <!-- Additional Help -->
        <div class="pt-6 border-t border-gray-200 dark:border-dark-border">
            <p class="text-sm text-gray-500 dark:text-gray-400">
                If you believe this is an error, please contact your administrator.
            </p>
        </div>
    </div>
</div>
