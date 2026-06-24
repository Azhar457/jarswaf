<script lang="ts">
  import Card from "./Card.svelte";

  export let logs: { level: "INFO" | "ERROR" | "WARN"; message: string; timestamp: string }[] = [];
  export let className: string = "";
</script>

<Card className={`p-0 overflow-hidden ${className}`}>
  <div class="bg-slate-900 border-b border-slate-800 px-4 py-2 flex items-center justify-between">
    <div class="flex items-center space-x-2">
      <div class="w-3 h-3 rounded-full bg-red-500/20 flex items-center justify-center">
        <div class="w-1.5 h-1.5 rounded-full bg-red-500"></div>
      </div>
      <span class="text-xs font-medium text-slate-400">Terminal - Event Logs</span>
    </div>
  </div>
  <div class="bg-slate-950 p-4 h-[300px] overflow-y-auto font-mono text-sm">
    {#if logs.length === 0}
      <div class="text-slate-500 italic text-center mt-10">No events recorded.</div>
    {/if}
    {#each logs as log}
      <div class="mb-1 leading-relaxed">
        <span class="text-slate-500 mr-2">[{log.timestamp}]</span>
        <span
          class={`font-semibold mr-2 ${
            log.level === "ERROR"
              ? "text-red-500"
              : log.level === "WARN"
                ? "text-amber-500"
                : "text-emerald-500"
          }`}>[{log.level}]</span
        >
        <span class="text-slate-300">{log.message}</span>
      </div>
    {/each}
  </div>
</Card>
