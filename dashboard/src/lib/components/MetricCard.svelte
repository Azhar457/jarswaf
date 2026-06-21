<script>
  /** @type {string} */
  export let label;
  /** @type {string} */
  export let value;
  /** @type {string} */
  export let subtext = '';
  /** @type {string} */
  export let icon;
  /** @type {string} */
  export let colorClass = 'text-primary';
  /** @type {number} */
  export let progress = -1;
  /** @type {string} */
  export let extraClass = '';

  $: bgClass = colorClass.replace('text-', 'bg-');
</script>

<div class="glass-panel p-6 rounded-xl {extraClass}">
  <div class="flex justify-between items-start mb-4">
    <span class="text-on-surface-variant text-[12px] font-bold uppercase tracking-widest">{label}</span>
    <span class="material-symbols-outlined {colorClass}">{icon}</span>
  </div>
  <div class="flex items-baseline gap-2">
    <h3 class="font-metric-lg text-metric-lg {colorClass}">{value}</h3>
    {#if subtext}
      <span class="{colorClass}/60 text-[11px] font-code-md font-mono">{subtext}</span>
    {/if}
  </div>
  {#if progress >= 0}
    <div class="mt-4 h-1 bg-surface-container rounded-full overflow-hidden">
      <div class="h-full {bgClass}" style="width: {progress}%"></div>
    </div>
  {/if}
</div>
