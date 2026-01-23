<script>
  import AppContent from './AppContent.svelte';
  import Toast, { setToastInstance } from '$lib/components/Toast.svelte';
  import { onMount } from 'svelte';

  let toastComponent;

  onMount(() => {
    if (toastComponent) {
        setToastInstance(toastComponent);
    }
  });
</script>

<AppContent />

<Toast bind:this={toastComponent} />
