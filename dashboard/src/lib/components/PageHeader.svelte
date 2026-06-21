<script>
  /** @type {{ label: string, active?: boolean }[]} */
  export let breadcrumbs = [];
  /** @type {string} */
  export let title;
  /** @type {string} */
  export let subtitle = '';
</script>

<div class="flex justify-between items-end mb-8">
  <div>
    {#if breadcrumbs.length > 0}
      <div class="flex items-center  text-on-surface-variant text-xs mb-2">
        {#each breadcrumbs as crumb, i}
          {#if i > 0}
            <span class="material-symbols-outlined text-[12px]">chevron_right</span>
          {/if}
          <span class={crumb.active ? 'text-primary' : ''}>{crumb.label}</span>
        {/each}
      </div>
    {/if}
    <h2 class="font-headline-md text-headline-md font-bold text-on-surface">{title}</h2>
    {#if subtitle}
      <p class="text-on-surface-variant font-body-sm text-body-sm mt-1">{subtitle}</p>
    {/if}
  </div>
  <slot name="actions" />
</div>
