<script lang="ts">
  import { onMount } from "svelte";
  import { stats, dbSize, logs, connectionStatus } from "./stores";

  export let controllerUrl = "";

  // Filter & Pagination states
  let filterText = "";
  let selectedAction = "All"; // 'All', 'BLOCK', 'RATE_LIMIT', 'PASS'
  let currentPage = 1;
  const itemsPerPage = 12;

  $: filteredLogs = $logs.filter((log) => {
    // Text filter
    const matchesText =
      filterText === "" ||
      log.client_ip.toLowerCase().includes(filterText.toLowerCase()) ||
      log.path.toLowerCase().includes(filterText.toLowerCase()) ||
      log.reason.toLowerCase().includes(filterText.toLowerCase()) ||
      log.rule_id.toLowerCase().includes(filterText.toLowerCase());

    // Action filter
    const matchesAction =
      selectedAction === "All" ||
      (selectedAction === "BLOCK" && log.action === "BLOCK") ||
      (selectedAction === "RATE_LIMIT" &&
        (log.action === "RATE_LIMIT" || log.action === "LIMIT" || log.action === "RATE")) ||
      (selectedAction === "PASS" &&
        (log.action === "PASS" || log.action === "ALLOW" || log.action === "REDIRECT"));

    return matchesText && matchesAction;
  });

  $: paginatedLogs = filteredLogs.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage,
  );

  $: totalPages = Math.max(1, Math.ceil(filteredLogs.length / itemsPerPage));

  // Reset page when filter changes
  $: if (filterText || selectedAction) {
    currentPage = 1;
  }

  async function handleExport() {
    try {
      window.location.href = `${controllerUrl}/api/v1/logs/export`;
    } catch (e) {
      console.error("Export logs error:", e);
      alert("Failed to export logs");
    }
  }

  function formatTime(timestamp: string): string {
    try {
      if (timestamp.includes("T")) {
        const parts = timestamp.split("T");
        const timePart = parts[1].split(".")[0];
        return `${parts[0]} ${timePart}`;
      }
      return timestamp;
    } catch {
      return timestamp;
    }
  }

  function formatCount(num: number): string {
    if (num < 1000) return num.toString();
    if (num < 1000000) {
      return (num / 1000).toFixed(1).replace(".0", "") + "k";
    }
    return (num / 1000000).toFixed(1).replace(".0", "") + "M";
  }

  function getRowClass(action: string): string {
    const act = action.toUpperCase();
    if (act === "BLOCK") return "action-block";
    if (act === "RATE_LIMIT" || act === "LIMIT" || act === "RATE") return "action-rate";
    return "action-pass";
  }

  function getBadgeClass(action: string): string {
    const act = action.toUpperCase();
    if (act === "BLOCK") return "text-error";
    if (act === "RATE_LIMIT" || act === "LIMIT" || act === "RATE") return "text-tertiary-container";
    return "text-primary";
  }

  function getBadgeDotClass(action: string): string {
    const act = action.toUpperCase();
    if (act === "BLOCK") return "bg-error";
    if (act === "RATE_LIMIT" || act === "LIMIT" || act === "RATE") return "bg-tertiary-container";
    return "bg-primary/40";
  }
</script>

<div class="live-logs-panel flex flex-col h-full gap-lg">
  <!-- Title section -->
  <div class="flex justify-between items-end">
    <div>
      <div class="flex items-center text-on-surface-variant text-xs mb-1">
        <span>Aegis WAF</span>
        <span class="material-symbols-outlined text-[12px]">chevron_right</span>
        <span class="text-primary">Live Threat Feed</span>
      </div>
      <h2 class="font-headline-md text-headline-md font-bold text-on-surface">Live Threat Feed</h2>
    </div>
  </div>

  <!-- TOOLBAR / FILTERS -->
  <div
    class="glass-panel p-md rounded-xl flex flex-col md:flex-row justify-between items-center gap-md"
  >
    <div class="flex flex-1 w-full md:w-auto items-center gap-md">
      <div class="relative flex-1 max-w-md">
        <span
          class="material-symbols-outlined absolute left-md top-1/2 -translate-y-1/2 text-on-surface-variant text-sm"
          >search</span
        >
        <input
          class="w-full bg-surface-container-lowest border border-outline-variant rounded-lg pl-xl pr-md py-sm font-body-sm text-on-surface focus:outline-none focus:border-primary-container transition-all"
          placeholder="Filter by Client IP, Path, or Reason..."
          bind:value={filterText}
          type="text"
        />
      </div>
      <div class="flex items-center gap-sm">
        <span class="text-on-surface-variant font-body-sm px-sm whitespace-nowrap">Status:</span>
        <select
          bind:value={selectedAction}
          class="bg-surface-container-lowest border border-outline-variant rounded-lg px-md py-sm font-body-sm text-on-surface focus:outline-none"
        >
          <option value="All">All Events</option>
          <option value="BLOCK">Blocked Only</option>
          <option value="RATE_LIMIT">Rate Limited</option>
          <option value="PASS">Passed Only</option>
        </select>
      </div>
    </div>

    <div class="flex items-center gap-md w-full md:w-auto justify-end">
      <button
        on:click={handleExport}
        class="bg-surface-container-high text-on-surface px-md py-sm rounded-lg font-body-sm border border-outline-variant flex items-center gap-sm hover:bg-surface-variant transition-all cursor-pointer"
      >
        <span class="material-symbols-outlined text-sm">download</span>
        Export Logs
      </button>
      <div class="h-8 w-1px bg-outline-variant mx-sm"></div>
      <div class="flex flex-col items-end">
        <span class="text-[10px] text-on-surface-variant uppercase tracking-tighter"
          >Filtered Events</span
        >
        <span class="text-primary font-metric-lg text-headline-md leading-none"
          >{filteredLogs.length}</span
        >
      </div>
    </div>
  </div>

  <!-- LIVE LOG TABLE -->
  <div class="glass-panel flex-1 rounded-xl overflow-hidden flex flex-col">
    <!-- Table Header -->
    <div
      class="bg-surface-container/50 border-b border-outline-variant px-lg py-sm grid grid-cols-12 gap-md items-center text-[11px] uppercase font-bold tracking-wider"
    >
      <div class="col-span-2 text-on-surface-variant">Timestamp</div>
      <div class="col-span-2 text-on-surface-variant">Client IP</div>
      <div class="col-span-1 text-on-surface-variant">Method</div>
      <div class="col-span-2 text-on-surface-variant">Path</div>
      <div class="col-span-1 text-on-surface-variant">Action</div>
      <div class="col-span-1 text-on-surface-variant">Rule ID</div>
      <div class="col-span-3 text-on-surface-variant text-right">Reason</div>
    </div>

    <!-- Table Rows -->
    <div class="flex-1 overflow-y-auto custom-scrollbar font-code-md text-code-md">
      {#each paginatedLogs as log}
        <div
          class="terminal-row {getRowClass(
            log.action,
          )} px-lg py-md grid grid-cols-12 gap-md items-center transition-colors"
        >
          <div class="col-span-2 text-on-surface/60">{formatTime(log.timestamp)}</div>
          <div class="col-span-2 text-primary font-bold">{log.client_ip}</div>
          <div class="col-span-1">
            <span class="px-sm py-0.5 rounded bg-surface-container text-[10px] font-bold font-sans"
              >{log.method}</span
            >
          </div>
          <div class="col-span-2 truncate font-mono" title={log.path}>{log.path}</div>
          <div class="col-span-1">
            <span class="{getBadgeClass(log.action)} font-bold flex items-center gap-xs">
              <span class="w-1.5 h-1.5 rounded-full {getBadgeDotClass(log.action)}"></span>
              {log.action}
            </span>
          </div>
          <div class="col-span-1 text-on-surface-variant font-mono">{log.rule_id || "--"}</div>
          <div
            class="col-span-3 text-right text-on-surface-variant truncate font-sans"
            title={log.reason}
          >
            {log.reason}
          </div>
        </div>
      {:else}
        <div class="text-on-surface-variant text-center py-20 italic">
          No logs found matching your filters
        </div>
      {/each}
    </div>

    <!-- TABLE FOOTER -->
    <div
      class="bg-surface-container-low border-t border-outline-variant px-lg py-xs flex justify-between items-center text-xs"
    >
      <div class="flex gap-md text-on-surface-variant font-code-md">
        <span>Buffer: {$logs.length} / 500 logs</span>
        <span>Storage size: {$dbSize}</span>
      </div>

      {#if totalPages > 1}
        <div class="flex gap-sm items-center">
          <button
            on:click={() => (currentPage = 1)}
            disabled={currentPage === 1}
            class="text-on-surface-variant hover:text-primary p-1 disabled:opacity-30 disabled:pointer-events-none cursor-pointer"
          >
            <span class="material-symbols-outlined text-[18px]">first_page</span>
          </button>
          <button
            on:click={() => (currentPage = Math.max(1, currentPage - 1))}
            disabled={currentPage === 1}
            class="text-on-surface-variant hover:text-primary p-1 disabled:opacity-30 disabled:pointer-events-none cursor-pointer"
          >
            <span class="material-symbols-outlined text-[18px]">chevron_left</span>
          </button>
          <span class="text-on-surface px-md text-code-md font-bold"
            >{currentPage} / {totalPages}</span
          >
          <button
            on:click={() => (currentPage = Math.min(totalPages, currentPage + 1))}
            disabled={currentPage === totalPages}
            class="text-on-surface-variant hover:text-primary p-1 disabled:opacity-30 disabled:pointer-events-none cursor-pointer"
          >
            <span class="material-symbols-outlined text-[18px]">chevron_right</span>
          </button>
          <button
            on:click={() => (currentPage = totalPages)}
            disabled={currentPage === totalPages}
            class="text-on-surface-variant hover:text-primary p-1 disabled:opacity-30 disabled:pointer-events-none cursor-pointer"
          >
            <span class="material-symbols-outlined text-[18px]">last_page</span>
          </button>
        </div>
      {/if}
    </div>
  </div>

  <!-- FOOTER / STATS -->
  <footer
    class="px-lg py-md bg-surface-container-lowest border-t border-outline-variant flex gap-xl overflow-x-auto custom-scrollbar rounded-xl"
  >
    <div class="shrink-0 flex items-center gap-md">
      <div class="p-sm bg-error/10 border border-error/20 rounded">
        <span class="material-symbols-outlined text-error">gpp_maybe</span>
      </div>
      <div>
        <div class="text-[10px] text-on-surface-variant uppercase font-bold tracking-widest">
          Blocks (24h)
        </div>
        <div class="text-headline-md font-metric-lg text-on-surface">
          {formatCount($stats.blocked)}
        </div>
      </div>
    </div>

    <div class="w-1px h-10 bg-outline-variant"></div>

    <div class="shrink-0 flex items-center gap-md">
      <div class="p-sm bg-tertiary-container/10 border border-tertiary-container/20 rounded">
        <span class="material-symbols-outlined text-tertiary-container">speed</span>
      </div>
      <div>
        <div class="text-[10px] text-on-surface-variant uppercase font-bold tracking-widest">
          Rate Limits
        </div>
        <div class="text-headline-md font-metric-lg text-on-surface">
          {formatCount($stats.rate_limited)}
        </div>
      </div>
    </div>

    <div class="w-1px h-10 bg-outline-variant"></div>

    <div class="shrink-0 flex items-center gap-md">
      <div class="p-sm bg-primary/10 border border-primary/20 rounded">
        <span class="material-symbols-outlined text-primary">public</span>
      </div>
      <div>
        <div class="text-[10px] text-on-surface-variant uppercase font-bold tracking-widest">
          Total Inspected
        </div>
        <div class="text-headline-md font-metric-lg text-on-surface">
          {formatCount($stats.total_requests)}
        </div>
      </div>
    </div>
  </footer>
</div>

<style>
  .glass-panel {
    background: rgba(13, 17, 23, 0.8);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-top: 1px solid rgba(255, 255, 255, 0.15);
  }

  .terminal-row {
    transition: background-color 0.2s ease;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }

  .terminal-row:hover {
    background-color: rgba(255, 255, 255, 0.02);
  }

  .action-block {
    border-left: 3px solid #ffb4ab;
    background: linear-gradient(90deg, rgba(255, 180, 171, 0.05) 0%, transparent 100%);
  }
  .action-rate {
    border-left: 3px solid #ffd8a7;
    background: linear-gradient(90deg, rgba(255, 216, 167, 0.05) 0%, transparent 100%);
  }
  .action-pass {
    border-left: 3px solid transparent;
  }
</style>
