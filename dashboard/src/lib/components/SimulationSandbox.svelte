<script lang="ts">
  import { createEventDispatcher } from "svelte";

  export let testPayload = "";
  export let simulationResult: {
    status: string;
    ruleName?: string;
  } = { status: "idle" };

  const dispatch = createEventDispatcher<{
    test: void;
  }>();

  function handleTest() {
    if (!testPayload) return;
    dispatch("test");
  }
</script>

<div class="glass-card rounded-xl p-4 border border-outline-variant/60">
  <div class="flex items-center mb-4 pb-1 border-b border-outline-variant/30">
    <span class="material-symbols-outlined text-primary text-md">science</span>
    <h4 class="font-bold text-sm tracking-tight text-on-surface">SIMULATION SANDBOX</h4>
  </div>
  <div class="space-y-4">
    <p class="text-[11px] text-on-surface-variant">
      Test payloads or paths against active modules and custom rules instantly:
    </p>

    <div class="relative">
      <textarea
        class="w-full bg-[#040508] border border-outline-variant rounded p-3 text-xs font-mono text-on-surface focus:border-primary outline-none h-20 resize-none"
        placeholder="Paste malicious payload or URL here (e.g. /wp-admin or ' OR 1=1)..."
        bind:value={testPayload}
      ></textarea>
      <button
        on:click={handleTest}
        class="absolute bottom-3 right-3 bg-surface-container-highest p-1.5 rounded hover:text-primary transition-colors cursor-pointer text-xs flex items-center gap-1 border-none text-on-surface-variant"
        title="Execute test"
      >
        <span class="material-symbols-outlined text-sm">play_arrow</span>
        <span>Test</span>
      </button>
    </div>

    {#if simulationResult.status === "testing"}
      <div
        class="flex items-center justify-center p-3 rounded bg-surface-container/30 border border-outline-variant"
      >
        <span
          class="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin mr-2"
        ></span>
        <span class="text-xs font-mono text-outline">Simulating enforcements...</span>
      </div>
    {:else if simulationResult.status === "triggered"}
      <div class="flex items-center justify-between p-3 rounded bg-error/10 border border-error/20">
        <div class="flex items-center">
          <span class="material-symbols-outlined text-error text-md">dangerous</span>
          <span class="text-xs font-bold text-error">DETECTION TRIGGERED</span>
        </div>
        <span
          class="text-[10px] font-mono text-on-surface-variant max-w-[180px] truncate"
          title={simulationResult.ruleName}
        >
          Rule: {simulationResult.ruleName}
        </span>
      </div>
    {:else if simulationResult.status === "passed"}
      <div
        class="flex items-center justify-between p-3 rounded bg-primary/10 border border-primary/20"
      >
        <div class="flex items-center">
          <span class="material-symbols-outlined text-primary text-md">check_circle</span>
          <span class="text-xs font-bold text-primary font-mono">REQUEST CLEARED</span>
        </div>
        <span class="text-[10px] font-mono text-on-surface-variant">No rules triggered</span>
      </div>
    {/if}
  </div>
</div>

<style>
  .glass-card {
    background: rgba(13, 17, 23, 0.7);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-top: 1px solid rgba(255, 255, 255, 0.15);
  }
</style>
