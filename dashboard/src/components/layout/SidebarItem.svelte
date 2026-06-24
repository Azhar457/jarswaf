<script lang="ts">
  import { createEventDispatcher } from "svelte";

  export let icon: any;
  export let label: string;
  export let active: boolean = false;
  export let isCollapsed: boolean = false;

  const dispatch = createEventDispatcher();
</script>

<button
  class={`w-full flex items-center px-4 py-3 cursor-pointer transition-colors border-l-4 ${
    active
      ? "bg-slate-800 border-blue-600 text-slate-100"
      : "border-transparent text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
  }`}
  on:click={() => dispatch("click")}
  title={isCollapsed ? label : undefined}
>
  <svelte:component this={icon} size={20} class={`shrink-0 ${active ? "text-blue-500" : ""}`} />
  {#if !isCollapsed}
    <span class="ml-3 font-medium text-sm whitespace-nowrap">{label}</span>
  {/if}
</button>
