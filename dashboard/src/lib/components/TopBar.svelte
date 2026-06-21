<script lang="ts">
  /** Number of attacks prevented, displayed formatted in the pill */
  export let blockedCount: number = 0;
  /** Whether the system is currently online */
  export let isOnline: boolean = true;

  function formatCount(num: number): string {
    if (num < 1000) return num.toString();
    if (num < 1000000) {
      return (num / 1000).toFixed(1).replace('.0', '') + 'k';
    }
    return (num / 1000000).toFixed(1).replace('.0', '') + 'M';
  }
</script>

<header class="flex justify-between items-center h-20 px-8 bg-surface/80 backdrop-blur-md sticky top-0 z-40 border-b border-outline-variant">
  <!-- Left: Search -->
  <div class="flex items-center gap-6">
    <div class="relative w-72">
      <!-- TODO: Implement global rules search functionality -->
      <!--
      <input
        class="w-full bg-surface-container-lowest border-outline-variant border rounded py-2 pl-10 pr-4 text-body-sm font-body-sm text-on-surface placeholder:text-on-surface-variant focus:ring-1 focus:ring-primary focus:outline-none"
        placeholder="Search rules..."
        type="text"
      />
      -->
    </div>
  </div>

  <!-- Right: Pills + Actions -->
  <div class="flex items-center gap-4">
    <!-- Attacks Prevented Pill -->
    <span class="text-xs px-4 py-2 bg-surface-container rounded border border-outline-variant text-on-surface-variant hidden sm:inline-block">
      Attacks Prevented: <strong class="text-error">{formatCount(blockedCount)}</strong>
    </span>

    <!-- System Status Pill -->
    <div class="flex items-center  px-4 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
      {#if isOnline}
        <span class="relative flex h-2.5 w-2.5">
          <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
          <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
        </span>
        <span class="text-[11px] font-bold text-emerald-400 uppercase tracking-wider font-mono">
          System Online
        </span>
      {:else}
        <span class="relative flex h-2.5 w-2.5">
          <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-error"></span>
        </span>
        <span class="text-[11px] font-bold text-error uppercase tracking-wider font-mono">
          System Offline
        </span>
      {/if}
    </div>

    <!-- Divider + Action Icons -->
    <!-- TODO: Connect System Logs terminal button to a modal or tab -->
    <!--
    <div class="flex  border-l border-outline-variant pl-4 text-on-surface-variant items-center">
      <button type="button" class="p-2 hover:text-primary transition-colors cursor-pointer" title="System Logs">
        <span class="material-symbols-outlined text-[20px]">terminal</span>
      </button>
    </div>
    -->
  </div>
</header>
