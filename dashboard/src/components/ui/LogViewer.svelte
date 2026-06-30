<script lang="ts">
  import Card from "./Card.svelte";

  export let logs: { level: "INFO" | "ERROR" | "WARN"; message: string; timestamp: string }[] = [];
  export let className: string = "";
  export let loading: boolean = false;
</script>

<Card className={`p-0 overflow-hidden ${className}`}>
  <div class="bg-slate-900/60 border-b border-border-muted/80 px-4 py-3 flex items-center justify-between">
    <div class="flex items-center space-x-2">
      <div class="w-3 h-3 rounded-full bg-error-bg flex items-center justify-center">
        <div class="w-1.5 h-1.5 rounded-full bg-error"></div>
      </div>
      <span class="text-xs font-bold text-text-secondary uppercase tracking-wider">Live Security Events Terminal</span>
    </div>
  </div>
  <div class="bg-slate-950/70 p-4 h-[350px] overflow-y-auto font-mono text-xs">
    {#if loading}
      {#each Array(8) as _}
        <div class="mb-3 animate-pulse flex space-x-2">
          <div class="h-4 bg-slate-800 rounded w-16"></div>
          <div class="h-4 bg-slate-800 rounded w-10"></div>
          <div class="h-4 bg-slate-800 rounded flex-1"></div>
        </div>
      {/each}
    {:else if logs.length === 0}
      <div class="flex flex-col items-center justify-center h-full text-text-muted italic gap-2 select-none">
        <p>Listening for incoming requests...</p>
        <div class="h-1.5 w-16 bg-slate-800 rounded-full overflow-hidden relative">
          <div class="absolute inset-y-0 bg-accent-blue/60 w-1/3 rounded-full animate-pulse"></div>
        </div>
      </div>
    {:else}
      {#each logs as log}
        <div class="mb-2 leading-relaxed border-b border-slate-900/40 pb-1.5 last:border-0 hover:bg-slate-900/20 px-1 rounded transition-colors duration-150">
          <span class="text-text-muted font-medium mr-2">[{log.timestamp}]</span>
          <span
            class={`font-bold mr-2 ${
              log.level === "ERROR"
                ? "text-error"
                : log.level === "WARN"
                  ? "text-warning"
                  : "text-success"
            }`}>[{log.level}]</span
          >
          <span class="text-text-primary">{log.message}</span>
        </div>
      {/each}
    {/if}
  </div>
</Card>
