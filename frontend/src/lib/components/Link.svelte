<script>
    import { router, navigate } from '$lib/router.svelte.js';
    
    let { href = '/', class: className = '', onclick = undefined, children } = $props();
    
    let isActive = $derived(router.path === href);
    
    function handleClick(e) {
        // Allow ctrl+click, cmd+click for new tab
        if (e.ctrlKey || e.metaKey || e.shiftKey) return;
        
        e.preventDefault();
        navigate(href);
        if (onclick) onclick(e);
    }
</script>

<a {href} class={className} onclick={handleClick}>
    {@render children()}
</a>
