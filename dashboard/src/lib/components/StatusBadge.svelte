<script>
  /** @type {string} */
  export let label;
  /** @type {'success' | 'error' | 'warning' | 'info'} */
  export let variant = 'info';
  /** @type {boolean} */
  export let dot = false;
  /** @type {boolean} */
  export let uppercase = true;

  /** @type {Record<string, { badge: string, dot: string }>} */
  const variantMap = {
    success: {
      badge: 'text-primary bg-primary/10 border-primary/20',
      dot: 'bg-primary'
    },
    error: {
      badge: 'text-error bg-error/10 border-error/20',
      dot: 'bg-error'
    },
    warning: {
      badge: 'text-tertiary-container bg-tertiary-container/10 border-tertiary-container/20',
      dot: 'bg-tertiary-container'
    },
    info: {
      badge: 'text-on-surface-variant bg-surface-container border-outline-variant',
      dot: 'bg-on-surface-variant'
    }
  };

  $: colors = variantMap[variant] || variantMap.info;
</script>

<span class="inline-flex items-center  px-4 py-2 rounded text-xs font-bold border {colors.badge} {uppercase ? 'uppercase' : ''}">
  {#if dot}
    <span class="w-2 h-2 rounded-full {colors.dot} {variant === 'success' ? 'animate-pulse' : ''}"></span>
  {/if}
  {label}
</span>
