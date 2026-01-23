<script>
    import Icon from './Icon.svelte';

    let { 
        open = $bindable(false),
        title = 'Confirm',
        message = 'Are you sure?',
        confirmText = 'Confirm',
        cancelText = 'Cancel',
        onConfirm = () => {},
        onCancel = () => {},
        type = 'warning' // warning, danger, info
    } = $props();

    function handleConfirm() {
        onConfirm();
        open = false;
    }

    function handleCancel() {
        onCancel();
        open = false;
    }

    const typeStyles = {
        warning: 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900/20',
        danger: 'text-red-600 bg-red-100 dark:bg-red-900/20',
        info: 'text-blue-600 bg-blue-100 dark:bg-blue-900/20'
    };

    const typeIcons = {
        warning: 'mdi:alert',
        danger: 'mdi:alert-circle',
        info: 'mdi:information'
    };
</script>

{#if open}
    <div class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-fade-in">
        <div class="bg-white dark:bg-dark-surface rounded-2xl shadow-2xl max-w-md w-full overflow-hidden animate-scale-in">
            <div class="p-6">
                <div class="flex items-start gap-4">
                    <div class={`p-3 rounded-full ${typeStyles[type]}`}>
                        <Icon icon={typeIcons[type]} class="w-6 h-6" />
                    </div>
                    <div class="flex-1">
                        <h3 class="text-lg font-bold text-gray-900 dark:text-white mb-2">{title}</h3>
                        <p class="text-sm text-gray-600 dark:text-gray-400">{message}</p>
                    </div>
                </div>
            </div>

            <div class="px-6 py-4 bg-gray-50 dark:bg-dark-bg/50 border-t border-gray-200 dark:border-dark-border flex justify-end gap-3">
                <button 
                    onclick={handleCancel}
                    class="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-border rounded-lg transition-colors font-medium"
                >
                    {cancelText}
                </button>
                <button 
                    onclick={handleConfirm}
                    class={`px-4 py-2 rounded-lg transition-colors font-medium ${
                        type === 'danger' 
                            ? 'bg-red-600 hover:bg-red-700 text-white' 
                            : 'bg-primary-600 hover:bg-primary-700 text-white'
                    }`}
                >
                    {confirmText}
                </button>
            </div>
        </div>
    </div>
{/if}

<style>
    @keyframes fade-in {
        from { opacity: 0; }
        to { opacity: 1; }
    }

    @keyframes scale-in {
        from {
            transform: scale(0.95);
            opacity: 0;
        }
        to {
            transform: scale(1);
            opacity: 1;
        }
    }

    .animate-fade-in {
        animation: fade-in 0.2s ease-out;
    }

    .animate-scale-in {
        animation: scale-in 0.2s ease-out;
    }
</style>
