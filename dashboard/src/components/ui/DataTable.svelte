<script lang="ts">
  export let columns: string[];
  export let className: string = "";
</script>

<div class={`overflow-x-auto rounded-xl border border-border-muted bg-slate-950/20 ${className}`}>
  <table class="w-full text-left text-sm text-text-secondary border-collapse">
    <thead class="text-xs text-text-secondary uppercase bg-slate-900/40 border-b border-border-muted">
      <tr>
        {#each columns as col}
          <th scope="col" class="px-6 py-4.5 font-bold tracking-wider">{col}</th>
        {/each}
      </tr>
    </thead>
    <tbody class="divide-y divide-border-muted/50 text-text-primary">
      <slot />
    </tbody>
  </table>
</div>
