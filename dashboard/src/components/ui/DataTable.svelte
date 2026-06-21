<script lang="ts">
  export let columns: string[];
  export let className: string = '';
</script>

<div class={`overflow-x-auto ${className}`}>
  <table class="w-full text-left text-sm text-slate-300">
    <thead class="text-xs text-slate-400 uppercase bg-slate-800/50 border-b border-slate-700/800">
      <tr>
        {#each columns as col}
          <th scope="col" class="px-6 py-4 font-medium tracking-wider">{col}</th>
        {/each}
      </tr>
    </thead>
    <tbody class="divide-y divide-slate-700/50">
      <slot />
    </tbody>
  </table>
</div>
