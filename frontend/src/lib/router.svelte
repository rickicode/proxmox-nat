<script module>
    // Simple router store for Svelte 5
    let currentPath = $state(typeof window !== 'undefined' ? window.location.pathname : '/');
    
    export function navigate(to, options = {}) {
        if (typeof window === 'undefined') return;
        
        if (options.replace) {
            window.history.replaceState({}, '', to);
        } else {
            window.history.pushState({}, '', to);
        }
        currentPath = to;
    }
    
    export function getCurrentPath() {
        return currentPath;
    }
    
    // Listen for popstate (back/forward navigation)
    if (typeof window !== 'undefined') {
        window.addEventListener('popstate', () => {
            currentPath = window.location.pathname;
        });
    }
</script>

<script>
    import { onMount } from 'svelte';
    
    let { href = '/', class: className = '', children } = $props();
    
    function handleClick(e) {
        // Allow ctrl+click, cmd+click for new tab
        if (e.ctrlKey || e.metaKey || e.shiftKey) return;
        
        e.preventDefault();
        navigate(href);
    }
</script>

<a {href} class={className} onclick={handleClick}>
    {@render children()}
</a>
