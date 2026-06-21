<script>
  /** @type {string} */
  export let padding = 'p-6';
  /** @type {string} */
  export let rounded = 'rounded-xl';
  /** @type {string} */
  export let extraClass = '';
</script>

<div class="glass-panel {padding} {rounded} {extraClass}">
  <slot />
</div>
