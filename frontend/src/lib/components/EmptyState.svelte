<script>
    import Icon from './Icon.svelte';

    let { 
        icon = 'mdi:inbox',
        title = 'No data',
        description = '',
        actionText = '',
        onAction = null
    } = $props();
</script>

<div class="flex flex-col items-center justify-center py-12 px-4 text-center">
    <div class="w-16 h-16 rounded-full bg-gray-100 dark:bg-gray-800 flex items-center justify-center mb-4">
        <Icon {icon} class="w-8 h-8 text-gray-400 dark:text-gray-600" />
    </div>
    <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">{title}</h3>
    {#if description}
        <p class="text-sm text-gray-500 dark:text-gray-400 mb-6 max-w-sm">{description}</p>
    {/if}
    {#if actionText && onAction}
        <button 
            onclick={onAction}
            class="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors shadow-lg shadow-primary-600/20"
        >
            <Icon icon="mdi:plus" class="w-4 h-4" />
            <span>{actionText}</span>
        </button>
    {/if}
</div>
