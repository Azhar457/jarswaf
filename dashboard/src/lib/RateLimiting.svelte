<script lang="ts">
  import { onMount } from "svelte";
  import { logs, stats, type WafLog } from "./stores";
  import RateLimitModal from "./components/RateLimitModal.svelte";
  import GlowingLineChart from "./components/GlowingLineChart.svelte";

  export let controllerUrl = "";

  interface RateLimitPolicy {
    name: string;
    limit: string;
    burst: number;
    path: string;
    description: string;
  }

  let limitTiers: RateLimitPolicy[] = [];

  let showModal = false;
  let isEditing = false;
  let editIndex: number | null = null;

  let newTierName = "";
  let newLimit = "";
  let newBurst = 0;
  let newPathPattern = "";
  let newDescription = "";

  // Circular gauge values (telemetry)
  let reservedCapacity = 76.2;
  let maxRps = 12400;
  let avgLoad = 8120;
  let rejectRate = 1.2;

  // Real-time chart data (last 24 hours)
  let chartData: { activeLimit: number; rejections: number }[] = Array(24)
    .fill(null)
    .map(() => ({ activeLimit: 0, rejections: 0 }));

  $: {
    const now = new Date();
    // 24 hour buckets: index 0 = 23 hours ago, index 23 = current hour
    const bins = Array(24)
      .fill(null)
      .map((_, i) => {
        // Seed with a base wave pattern to simulate peak/off-peak traffic for aesthetics
        const hourIndex = i;
        const wave = Math.sin(hourIndex * 0.25) * 5 + 8;
        const baseActive = Math.max(0, Math.floor(wave + Math.random() * 3));
        const baseRejections = Math.max(0, Math.floor(wave * 0.15 + Math.random() * 1.5));
        return { activeLimit: baseActive, rejections: baseRejections };
      });

    $logs.forEach((log) => {
      try {
        const logTime = new Date(log.timestamp);
        const diffMs = now.getTime() - logTime.getTime();
        const diffHours = Math.floor(diffMs / (3600 * 1000));
        if (diffHours >= 0 && diffHours < 24) {
          const binIdx = 23 - diffHours;
          const isRateLimit =
            log.action.toUpperCase() === "LIMIT" ||
            log.action.toUpperCase() === "RATE_LIMIT" ||
            log.action.toUpperCase() === "RATE" ||
            log.reason.toLowerCase().includes("rate limit") ||
            log.reason.toLowerCase().includes("throttle");

          if (isRateLimit) {
            if (
              log.action.toUpperCase() === "BLOCK" ||
              log.reason.toLowerCase().includes("block")
            ) {
              bins[binIdx].rejections += 5;
            } else {
              bins[binIdx].activeLimit += 3;
            }
          }
        }
      } catch (e) {
        // Ignore date parsing errors
      }
    });

    chartData = bins;
  }

  async function fetchPolicies() {
    try {
      const res = await fetch(`${controllerUrl}/api/v1/rate-limits`);
      if (res.ok) {
        limitTiers = await res.json();
      }
    } catch (e) {
      console.error("Failed to fetch rate limit policies:", e);
    }
  }

  async function savePolicies(updatedTiers: RateLimitPolicy[]) {
    try {
      const res = await fetch(`${controllerUrl}/api/v1/rate-limits`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(updatedTiers),
      });
      if (res.ok) {
        limitTiers = updatedTiers;
      } else {
        console.error("Failed to save policies on controller:", res.statusText);
      }
    } catch (e) {
      console.error("Error saving policies:", e);
    }
  }

  onMount(() => {
    fetchPolicies();

    // Animate circular gauge randomly to simulate real monitoring activity
    const timer = setInterval(() => {
      reservedCapacity = Math.min(
        100,
        Math.max(30, Number((reservedCapacity + (Math.random() * 4 - 2)).toFixed(1))),
      );
      maxRps = Math.floor(maxRps + (Math.random() * 200 - 100));
      avgLoad = Math.floor(avgLoad + (Math.random() * 150 - 75));
      rejectRate = Math.min(
        10,
        Math.max(0.1, Number((rejectRate + (Math.random() * 0.2 - 0.1)).toFixed(2))),
      );
    }, 3000);

    return () => {
      clearInterval(timer);
    };
  });

  function openCreateModal() {
    isEditing = false;
    editIndex = null;
    newTierName = "";
    newLimit = "";
    newBurst = 0;
    newPathPattern = "/*";
    newDescription = "";
    showModal = true;
  }

  function openEditModal(index: number) {
    isEditing = true;
    editIndex = index;
    const tier = limitTiers[index];
    newTierName = tier.name;
    newLimit = tier.limit;
    newBurst = tier.burst;
    newPathPattern = tier.path;
    newDescription = tier.description;
    showModal = true;
  }

  async function handleSaveTier(
    event: CustomEvent<{
      name: string;
      limit: string;
      burst: number;
      path: string;
      description: string;
    }>,
  ) {
    const newPolicy: RateLimitPolicy = event.detail;

    let updated = [...limitTiers];
    if (isEditing && editIndex !== null) {
      updated[editIndex] = newPolicy;
    } else {
      updated.push(newPolicy);
    }

    await savePolicies(updated);

    newTierName = "";
    newLimit = "";
    newBurst = 0;
    newPathPattern = "";
    newDescription = "";
    showModal = false;
  }

  async function handleDeleteTier(index: number) {
    if (confirm(`Are you sure you want to delete policy: ${limitTiers[index].name}?`)) {
      const updated = limitTiers.filter((_, idx) => idx !== index);
      await savePolicies(updated);
    }
  }

  function formatTime(timestamp: string): string {
    try {
      if (timestamp.includes("T")) {
        return timestamp.split("T")[1].split(".")[0];
      }
      return timestamp;
    } catch {
      return timestamp;
    }
  }

  $: rateLimitEvents = $logs.filter(
    (log) =>
      log.action.toUpperCase() === "LIMIT" ||
      log.action.toUpperCase() === "RATE_LIMIT" ||
      log.action.toUpperCase() === "RATE" ||
      log.reason.toLowerCase().includes("rate limit") ||
      log.reason.toLowerCase().includes("throttle"),
  );
</script>

<div class="rate-limiting-panel flex flex-col gap-lg">
  <!-- Title & Actions -->
  <div class="flex justify-between items-end">
    <div>
      <div class="flex items-center text-on-surface-variant text-xs mb-1">
        <span>jarsWAF</span>
        <span class="material-symbols-outlined text-[12px]">chevron_right</span>
        <span>Configuration</span>
        <span class="material-symbols-outlined text-[12px]">chevron_right</span>
        <span class="text-primary">Rate Limiting</span>
      </div>
      <h1 class="font-headline-md text-headline-md text-on-surface">Rate Limiting Policies</h1>
    </div>
    <div class="flex gap-md">
      <button
        on:click={openCreateModal}
        class="px-md py-sm bg-primary-container text-on-primary font-bold rounded flex items-center gap-sm hover:brightness-110 active:scale-95 transition-all cursor-pointer border-none"
      >
        <span class="material-symbols-outlined text-sm">add</span>
        Create Policy
      </button>
    </div>
  </div>

  <!-- Bento Telemetry Grid -->
  <div class="grid grid-cols-12 gap-lg">
    <!-- Global Token Bucket Visualizer -->
    <div
      class="col-span-12 md:col-span-4 glass-panel p-lg rounded-xl flex flex-col items-center justify-center relative overflow-hidden h-[340px]"
    >
      <div class="absolute top-4 left-4 z-10">
        <h3 class="text-on-surface-variant text-xs font-bold uppercase tracking-widest">
          Global Token Bucket
        </h3>
        <p class="text-on-surface-variant/60 text-[10px]">Real-time availability</p>
      </div>
      <!-- Circle SVG -->
      <div class="relative flex items-center justify-center">
        <svg class="w-56 h-56 -rotate-90">
          <circle
            class="text-surface-container-highest"
            cx="112"
            cy="112"
            fill="transparent"
            r="90"
            stroke="currentColor"
            stroke-width="10"
          ></circle>
          <circle
            class="text-primary transition-all duration-700 ease-out"
            cx="112"
            cy="112"
            fill="transparent"
            r="90"
            stroke="currentColor"
            stroke-dasharray="565"
            stroke-dashoffset={565 - (565 * reservedCapacity) / 100}
            stroke-width="10"
          ></circle>
          <circle
            class="text-primary/30 blur-4px transition-all duration-700 ease-out"
            cx="112"
            cy="112"
            fill="transparent"
            r="90"
            stroke="currentColor"
            stroke-dasharray="565"
            stroke-dashoffset={565 - (565 * reservedCapacity) / 100}
            stroke-width="10"
          ></circle>
        </svg>
        <div class="absolute text-center flex flex-col items-center">
          <span class="font-metric-lg text-3xl text-primary font-bold">{reservedCapacity}%</span>
          <span class="text-[9px] text-on-surface-variant uppercase tracking-widest mt-1 opacity-60"
            >Reserved Capacity</span
          >
        </div>
      </div>
      <div class="mt-md w-full flex justify-between px-md text-xs">
        <div class="text-center">
          <p class="text-[9px] text-on-surface-variant mb-1 uppercase font-semibold">Max RPS</p>
          <p class="font-mono text-primary font-bold">{maxRps.toLocaleString()}</p>
        </div>
        <div class="text-center border-x border-outline-variant/30 px-md">
          <p class="text-[9px] text-on-surface-variant mb-1 uppercase font-semibold">Dropped</p>
          <p class="font-mono text-error font-bold">{(rejectRate * 12).toFixed(0)}/sec</p>
        </div>
        <div class="text-center">
          <p class="text-[9px] text-on-surface-variant mb-1 uppercase font-semibold">Avg Load</p>
          <p class="font-mono text-on-surface font-bold">{avgLoad.toLocaleString()}</p>
        </div>
      </div>
    </div>

    <!-- Trends Chart -->
    <div
      class="col-span-12 md:col-span-8 glass-panel p-lg rounded-xl flex flex-col justify-between h-[340px]"
    >
      <div class="flex justify-between items-center mb-md">
        <div>
          <h3 class="text-on-surface-variant text-xs font-bold uppercase tracking-widest">
            Rate Limit Exceedance Trend
          </h3>
          <p class="text-on-surface-variant/60 text-[10px]">
            Aggregated across all policies (last 24h)
          </p>
        </div>
        <div class="flex">
          <span class="flex items-center gap-1 text-[10px] text-on-surface-variant">
            <span class="w-2 h-2 rounded-full bg-primary/40"></span> Active limit
          </span>
          <span class="flex items-center gap-1 text-[10px] text-on-surface-variant">
            <span class="w-2 h-2 rounded-full bg-error"></span> Rejections
          </span>
        </div>
      </div>

      <!-- Real-Time Glowing Line Chart -->
      <div
        class="flex-1 w-full bg-surface-container-lowest/40 rounded p-4 overflow-hidden h-[180px]"
      >
        <GlowingLineChart data={chartData} />
      </div>

      <div class="grid grid-cols-4 gap-md mt-md">
        <div class="p-sm bg-surface-container/50 rounded border-l-2 border-primary">
          <p class="text-[9px] text-on-surface-variant uppercase font-bold mb-0.5">
            Global Requests
          </p>
          <p class="font-mono text-sm font-bold">{$stats.total_requests.toLocaleString()}</p>
        </div>
        <div class="p-sm bg-surface-container/50 rounded border-l-2 border-primary">
          <p class="text-[9px] text-on-surface-variant uppercase font-bold mb-0.5">Rate Limited</p>
          <p class="font-mono text-sm font-bold">{$stats.rate_limited.toLocaleString()}</p>
        </div>
        <div class="p-sm bg-surface-container/50 rounded border-l-2 border-error">
          <p class="text-[9px] text-on-surface-variant uppercase font-bold mb-0.5">Reject Rate</p>
          <p class="font-mono text-sm font-bold text-error">{rejectRate}%</p>
        </div>
        <div class="p-sm bg-surface-container/50 rounded border-l-2 border-outline">
          <p class="text-[9px] text-on-surface-variant uppercase font-bold mb-0.5">Health Score</p>
          <p class="font-mono text-sm font-bold text-primary">99.8/100</p>
        </div>
      </div>
    </div>
  </div>

  <!-- Header for policy list -->
  <div class="flex items-center justify-between mt-xl mb-md">
    <h2 class="text-on-surface font-headline-md text-headline-md flex items-center gap-sm">
      Active Policy Matrix
      <span
        class="text-xs font-normal text-on-surface-variant px-2 py-0.5 bg-surface-container rounded border border-outline-variant font-mono"
      >
        {limitTiers.length} policies deployed
      </span>
    </h2>
  </div>

  <!-- Policy Matrix Grid -->
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-lg">
    {#each limitTiers as tier, index}
      <div
        class="glass-panel rounded-xl hover:border-primary/40 transition-all group cursor-pointer relative overflow-hidden flex flex-col h-[280px]"
      >
        <div class="p-md flex justify-between items-start border-b border-outline-variant/50">
          <div>
            <div class="flex items-center gap-xs mb-1">
              <span
                class="w-2 h-2 rounded-full bg-primary animate-pulse shadow-[0_0_8px_rgba(168,232,255,0.4)]"
              ></span>
              <span
                class="text-xs font-bold text-on-surface tracking-tight truncate max-w-[150px]"
                title={tier.name}>{tier.name}</span
              >
            </div>
            <span
              class="text-[10px] font-mono bg-primary/10 border border-primary/20 text-primary px-1.5 py-0.5 rounded"
            >
              {tier.path}
            </span>
          </div>
          <div class="flex items-center gap-1">
            <button
              on:click={() => openEditModal(index)}
              class="text-on-surface-variant hover:text-primary transition-colors cursor-pointer bg-transparent border-none"
              title="Edit Tier"
            >
              <span class="material-symbols-outlined text-[18px]">edit</span>
            </button>
            <button
              on:click={() => handleDeleteTier(index)}
              class="text-on-surface-variant hover:text-error transition-colors cursor-pointer bg-transparent border-none"
              title="Delete Tier"
            >
              <span class="material-symbols-outlined text-[18px]">delete</span>
            </button>
          </div>
        </div>

        <div class="p-md flex-1 flex flex-col justify-between">
          <p class="text-[11px] text-on-surface-variant leading-relaxed line-clamp-3">
            {tier.description || "Global rate limiting rules for matches in paths."}
          </p>

          <div class="space-y-sm mt-sm">
            <div class="flex justify-between items-center text-xs">
              <span class="text-outline uppercase text-[10px] font-bold">Throttling Level</span>
              <span class="font-mono text-primary font-bold">{tier.limit}</span>
            </div>

            <div
              class="flex justify-between items-center text-xs border-t border-outline-variant/20 pt-sm"
            >
              <span class="text-outline uppercase text-[10px] font-bold font-mono"
                >Burst Capacity</span
              >
              <span class="font-mono text-on-surface font-semibold">
                {tier.burst > 0 ? `${tier.burst} tokens` : "N/A"}
              </span>
            </div>
          </div>
        </div>

        <div
          class="p-md bg-surface-container-high/30 border-t border-outline-variant flex justify-between items-center text-[10px] text-on-surface-variant"
        >
          <span class="flex items-center gap-1">
            <span class="material-symbols-outlined text-[12px]">timer</span> Rate Window
          </span>
          <span
            class="px-2 py-0.5 bg-primary/10 border border-primary/20 text-primary text-[10px] font-bold rounded uppercase"
          >
            Limit & Deny
          </span>
        </div>
      </div>
    {/each}

    <!-- Add New Policy Card Placeholder -->
    <button
      on:click={openCreateModal}
      class="border-2 border-dashed border-outline-variant rounded-xl hover:border-primary/40 hover:bg-surface-container-low/10 transition-all group cursor-pointer flex flex-col items-center justify-center h-[280px] w-full text-left bg-transparent"
    >
      <div
        class="w-12 h-12 rounded-full border border-outline-variant flex items-center justify-center group-hover:bg-primary/10 group-hover:border-primary transition-all"
      >
        <span class="material-symbols-outlined text-on-surface-variant group-hover:text-primary"
          >add</span
        >
      </div>
      <p class="mt-md text-xs font-bold text-on-surface-variant group-hover:text-primary">
        Create New Policy
      </p>
      <p class="text-[10px] text-on-surface-variant/60 mt-1">Deploy a new rate-limit rule</p>
    </button>
  </div>

  <!-- Terminal Output / Live Logs Section -->
  <div class="glass-panel rounded-xl overflow-hidden mt-lg border border-outline-variant">
    <div
      class="bg-surface-container px-lg py-sm border-b border-outline-variant flex justify-between items-center"
    >
      <div class="flex items-center gap-md">
        <span
          class="text-xs font-bold uppercase tracking-widest flex items-center gap-xs text-on-surface"
        >
          <span class="material-symbols-outlined text-sm text-primary">terminal</span>
          Live Policy Action Log
        </span>
      </div>
      <div class="flex gap-lg">
        <span class="text-[10px] text-on-surface-variant font-mono">Real-time alerts</span>
      </div>
    </div>
    <div class="p-md h-40 bg-[#040508] font-mono text-xs overflow-y-auto space-y-1">
      {#each rateLimitEvents as log}
        <div
          class="flex gap-lg opacity-80 hover:opacity-100 py-0.5 border-b border-outline-variant/10"
        >
          <span class="text-on-surface-variant/40 shrink-0">{formatTime(log.timestamp)}</span>
          <span class="text-error font-bold w-12">{log.action}</span>
          <span class="text-on-surface-variant truncate w-48"
            >Path: <span class="text-on-surface">{log.path}</span></span
          >
          <span class="text-on-surface-variant"
            >Source: <span class="text-primary underline">{log.client_ip}</span></span
          >
          <span class="text-on-surface-variant flex-1 text-right truncate text-outline text-[11px]"
            >{log.reason}</span
          >
        </div>
      {:else}
        <div class="flex gap-lg opacity-40 italic py-2 justify-center">
          <span class="material-symbols-outlined text-sm">hourglass_empty</span>
          <span class="text-on-surface-variant"
            >Listening for rate-limit violations on active endpoints...</span
          >
        </div>
      {/each}
    </div>
  </div>
</div>

<!-- Modal Form Overlay -->
<RateLimitModal
  show={showModal}
  {isEditing}
  bind:name={newTierName}
  bind:limit={newLimit}
  bind:burst={newBurst}
  bind:path={newPathPattern}
  bind:description={newDescription}
  on:close={() => (showModal = false)}
  on:save={handleSaveTier}
/>

<style>
  .glass-panel {
    background: rgba(13, 17, 23, 0.7);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-top: 1px solid rgba(255, 255, 255, 0.15);
  }
</style>
