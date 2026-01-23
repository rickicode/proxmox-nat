<script>
    import IconifyIcon from '@iconify/svelte';
    
    let { 
        icon, 
        class: className = '', 
        size = 24,
        ...rest 
    } = $props();
    
    // Convert size to width/height if needed
    let iconSize = $derived(typeof size === 'number' ? `${size}px` : size);
</script>

<IconifyIcon 
    {icon} 
    class={className}
    width={iconSize}
    height={iconSize}
    {...rest}
/>
