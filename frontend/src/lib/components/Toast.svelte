<script>
    let toasts = $state([]);
    let nextId = 0;

    export function addToast(message, type = 'info', duration = 3000) {
        const id = nextId++;
        const toast = { id, message, type };
        toasts.push(toast);
        toasts = toasts; // Trigger reactivity

        if (duration > 0) {
            setTimeout(() => removeToast(id), duration);
        }

        return id;
    }

    export function removeToast(id) {
        toasts = toasts.filter(t => t.id !== id);
    }

    const typeStyles = {
        success: 'bg-green-50 dark:bg-green-900/20 text-green-800 dark:text-green-200 border-green-200 dark:border-green-800',
        error: 'bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-200 border-red-200 dark:border-red-800',
        warning: 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200 border-yellow-200 dark:border-yellow-800',
        info: 'bg-blue-50 dark:bg-blue-900/20 text-blue-800 dark:text-blue-200 border-blue-200 dark:border-blue-800'
    };

    const typeIcons = {
        success: 'mdi:check-circle',
        error: 'mdi:alert-circle',
        warning: 'mdi:alert',
        info: 'mdi:information'
    };
</script>

<div class="fixed top-4 right-4 z-50 space-y-2 max-w-sm w-full pointer-events-none">
    {#each toasts as toast (toast.id)}
        <div 
            class={`pointer-events-auto flex items-start gap-3 p-4 rounded-lg border shadow-lg backdrop-blur-sm animate-slide-in ${typeStyles[toast.type]}`}
            role="alert"
        >
            <Icon icon={typeIcons[toast.type]} class="w-5 h-5 flex-shrink-0 mt-0.5" />
            <p class="flex-1 text-sm font-medium">{toast.message}</p>
            <button 
                onclick={() => removeToast(toast.id)}
                class="flex-shrink-0 opacity-70 hover:opacity-100 transition-opacity"
            >
                <Icon icon="mdi:close" class="w-4 h-4" />
            </button>
        </div>
    {/each}
</div>

<style>
    @keyframes slide-in {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    .animate-slide-in {
        animation: slide-in 0.3s ease-out;
    }
</style>

<script module>
    import Icon from './Icon.svelte';
    
    let toastInstance;
    
    export function toast(message, type = 'info', duration = 3000) {
        if (toastInstance) {
            return toastInstance.addToast(message, type, duration);
        }
    }
    
    export function setToastInstance(instance) {
        toastInstance = instance;
    }
</script>
