<script>
    let { rows = 3 } = $props();
</script>

<div class="space-y-4 animate-pulse">
    {#each Array(rows) as _}
        <div class="bg-white dark:bg-dark-surface p-4 rounded-xl border border-gray-200 dark:border-dark-border">
            <div class="flex items-center gap-4">
                <div class="w-12 h-12 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
                <div class="flex-1 space-y-2">
                    <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/4"></div>
                    <div class="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
                </div>
                <div class="flex gap-2">
                    <div class="w-8 h-8 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
                    <div class="w-8 h-8 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
                    <div class="w-8 h-8 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
                </div>
            </div>
        </div>
    {/each}
</div>
