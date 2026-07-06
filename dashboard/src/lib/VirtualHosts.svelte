<script lang="ts">
  import { onMount } from "svelte";
  import VirtualHostModal from "./components/VirtualHostModal.svelte";

  export let controllerUrl = "";
  let vhosts: any[] = [];
  let searchQuery = "";
  let expandedHosts: { [key: string]: boolean } = {};

  let showModal = false;
  let isEditing = false;
  let editIndex: number | null = null;

  let newServerName = "";
  let newUpstream = "";
  let newSsl = "Auto (Local CA)";
  let newMaxBody = "10MB";
  let newRateLimit = "600 req/min";
  let blockedCountries: string[] = [];
  let geoblockType = "Blocklist";

  // Batching Mode Category Selection
  let selectedCategories = {
    sqli: true,
    xss: true,
    lfi: true,
    cmdi: false,
    ssrf: false,
    bot: false,
  };

  const availableCountries = [
    { code: "US", name: "United States", flag: "🇺🇸" },
    { code: "CN", name: "China", flag: "🇨🇳" },
    { code: "RU", name: "Russia", flag: "🇷🇺" },
    { code: "DE", name: "Germany", flag: "🇩🇪" },
    { code: "SG", name: "Singapore", flag: "🇸🇬" },
    { code: "ID", name: "Indonesia", flag: "🇮🇩" },
    { code: "BR", name: "Brazil", flag: "🇧🇷" },
    { code: "AU", name: "Australia", flag: "🇦🇺" },
  ];

  const flags: { [code: string]: string } = {
    US: "🇺🇸",
    DE: "🇩🇪",
    RU: "🇷🇺",
    CN: "🇨🇳",
    SG: "🇸🇬",
    ID: "🇮🇩",
    BR: "🇧🇷",
    AU: "🇦🇺",
  };

  async function fetchVhosts() {
    try {
      const res = await fetch(`${controllerUrl}/api/v1/vhosts`);
      if (res.ok) {
        const raw = await res.json();
        vhosts = raw.map((item: any) => ({
          server_name: item.hosts && item.hosts.length > 0 ? item.hosts[0] : item.name,
          upstream: item.backend,
          ssl: item.ssl || "Disabled",
          max_body: item.max_body || "10MB",
          rate_limit: item.rate_limit || "600 req/min",
          rules: item.rules || [],
          blocked_countries: item.blocked_countries || [],
          geoblock_type: item.geoblock_type || "Blocklist",
          custom_rules: item.custom_rules || [],
          rate_limit_tiers: item.rate_limit_tiers || [],
          logging: item.logging || null,
          status: "online",
        }));
      }
    } catch (e) {
      console.error("Failed to fetch virtual hosts:", e);
    }
  }

  async function saveVhosts(updatedVhosts: any[]) {
    const payload = updatedVhosts.map((item: any) => ({
      name: item.server_name.replace(/[^a-zA-Z0-9.-]/g, "_").toLowerCase(),
      hosts: [item.server_name],
      backend: item.upstream,
      ssl: item.ssl,
      max_body: item.max_body,
      rate_limit: item.rate_limit,
      rules: item.rules,
      blocked_countries: item.blocked_countries || [],
      geoblock_type: item.geoblock_type || "Blocklist",
      custom_rules: item.custom_rules || [],
      rate_limit_tiers: item.rate_limit_tiers || [],
      logging: item.logging || { enabled: true, db_path: "logs/jarswaf.db" },
    }));

    try {
      const res = await fetch(`${controllerUrl}/api/v1/vhosts`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        await fetchVhosts();
      } else {
        console.error("Failed to save virtual hosts");
      }
    } catch (e) {
      console.error("Error saving virtual hosts:", e);
    }
  }

  onMount(() => {
    fetchVhosts();
  });

  function toggleDetails(serverName: string) {
    expandedHosts[serverName] = !expandedHosts[serverName];
  }

  function openCreateModal() {
    isEditing = false;
    editIndex = null;
    newServerName = "";
    newUpstream = "";
    newSsl = "Auto (Local CA)";
    newMaxBody = "10MB";
    newRateLimit = "600 req/min";
    blockedCountries = [];
    geoblockType = "Blocklist";
    selectedCategories = {
      sqli: true,
      xss: true,
      lfi: true,
      cmdi: false,
      ssrf: false,
      bot: false,
    };
    showModal = true;
  }

  function openEditModal(index: number, event: Event) {
    event.stopPropagation();
    isEditing = true;
    editIndex = index;
    const host = vhosts[index];

    newServerName = host.server_name;
    newUpstream = host.upstream;
    newSsl = host.ssl;
    newMaxBody = host.max_body;
    newRateLimit = host.rate_limit;
    blockedCountries = host.blocked_countries || [];
    geoblockType = host.geoblock_type || "Blocklist";

    selectedCategories = {
      sqli: host.rules.includes("SQLI-*"),
      xss: host.rules.includes("XSS-*"),
      lfi: host.rules.includes("LFI-*") || host.rules.includes("RFI-*"),
      cmdi: host.rules.includes("CMDI-*"),
      ssrf: host.rules.includes("SSRF-*"),
      bot: host.rules.includes("BOT-*"),
    };
    showModal = true;
  }

  function duplicateVhost(index: number, event: Event) {
    event.stopPropagation();
    const host = vhosts[index];
    isEditing = false;
    editIndex = null;

    newServerName = host.server_name + "-copy";
    newUpstream = host.upstream;
    newSsl = host.ssl;
    newMaxBody = host.max_body;
    newRateLimit = host.rate_limit;
    blockedCountries = [...(host.blocked_countries || [])];
    geoblockType = host.geoblock_type || "Blocklist";

    selectedCategories = {
      sqli: host.rules.includes("SQLI-*"),
      xss: host.rules.includes("XSS-*"),
      lfi: host.rules.includes("LFI-*") || host.rules.includes("RFI-*"),
      cmdi: host.rules.includes("CMDI-*"),
      ssrf: host.rules.includes("SSRF-*"),
      bot: host.rules.includes("BOT-*"),
    };
    showModal = true;
  }

  function handleDeleteVhost(index: number, event: Event) {
    event.stopPropagation();
    if (!confirm(`Are you sure you want to delete virtual host: ${vhosts[index].server_name}?`))
      return;
    const updated = vhosts.filter((_, i) => i !== index);
    saveVhosts(updated);
  }

  function toggleCountry(code: string, checked: boolean) {
    if (checked) {
      blockedCountries = [...blockedCountries, code];
    } else {
      blockedCountries = blockedCountries.filter((c) => c !== code);
    }
  }

  function handleSaveVhost() {
    if (!newServerName || !newUpstream) return;

    // Compile active wildcard pattern rules based on batch checkboxes
    let activeRules: string[] = [];
    if (selectedCategories.sqli) activeRules.push("SQLI-*");
    if (selectedCategories.xss) activeRules.push("XSS-*");
    if (selectedCategories.lfi) {
      activeRules.push("LFI-*");
      activeRules.push("RFI-*");
    }
    if (selectedCategories.cmdi) activeRules.push("CMDI-*");
    if (selectedCategories.ssrf) activeRules.push("SSRF-*");
    if (selectedCategories.bot) activeRules.push("BOT-*");

    const hostData = {
      server_name: newServerName,
      upstream: newUpstream,
      ssl: newSsl,
      max_body: newMaxBody,
      rate_limit: newRateLimit,
      rules: activeRules,
      blocked_countries: blockedCountries,
      geoblock_type: geoblockType,
      custom_rules: isEditing && editIndex !== null ? vhosts[editIndex].custom_rules : [],
      rate_limit_tiers: isEditing && editIndex !== null ? vhosts[editIndex].rate_limit_tiers : [],
      logging: isEditing && editIndex !== null ? vhosts[editIndex].logging : null,
      status: "online",
    };

    let updated = [...vhosts];
    if (isEditing && editIndex !== null) {
      updated[editIndex] = hostData;
    } else {
      updated.push(hostData);
    }

    saveVhosts(updated);
    showModal = false;
  }

  $: filteredVhosts = vhosts.filter(
    (h) =>
      h.server_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      h.upstream.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  $: totalCerts = vhosts.filter((h) => h.ssl !== "Disabled").length;
</script>

<!-- Main Header -->
<div class="flex justify-between items-end mb-lg">
  <div>
    <div class="flex items-center text-on-surface-variant text-xs mb-1">
      <span>jarsWAF</span>
      <span class="material-symbols-outlined text-[12px]">chevron_right</span>
      <span>Configuration</span>
      <span class="material-symbols-outlined text-[12px]">chevron_right</span>
      <span class="text-primary">VHost Settings</span>
    </div>
    <h2 class="font-headline-md text-headline-md text-on-surface mb-xs">VHost Configuration</h2>
    <p class="text-on-surface-variant font-body-sm opacity-70">
      Manage virtual host routing, SSL, and protection parameters for backend groups.
    </p>
  </div>
  <div class="flex gap-md">
    <div
      class="flex items-center gap-sm px-md py-sm bg-surface-container-low border border-outline-variant rounded"
    >
      <span class="material-symbols-outlined text-on-surface-variant text-[20px]">search</span>
      <input
        class="bg-transparent border-none focus:ring-0 text-sm p-0 text-on-surface placeholder:text-outline w-48 outline-none"
        placeholder="Filter VHosts..."
        type="text"
        bind:value={searchQuery}
      />
    </div>
    <button
      on:click={openCreateModal}
      class="px-lg py-sm bg-primary text-background font-bold text-sm rounded flex items-center active:scale-95 transition-all cursor-pointer border-none"
    >
      <span class="material-symbols-outlined text-[18px]">add</span>
      Create VHost
    </button>
  </div>
</div>

<!-- SSL Health Banner -->
{#if vhosts.some((h) => h.ssl !== "Disabled" && h.ssl.includes("Expired"))}
  <div
    class="glass-panel rounded-xl p-md mb-lg flex items-center justify-between border-l-4 border-l-error bg-error/5"
  >
    <div class="flex items-center gap-md">
      <span class="material-symbols-outlined text-error">warning</span>
      <div>
        <p class="font-bold text-sm text-error">SSL Certificate Attention Required</p>
        <p class="text-xs text-on-surface-variant">
          Expired or invalid certificates detected in active routing endpoints.
        </p>
      </div>
    </div>
  </div>
{/if}

<!-- Management Table -->
<div class="glass-panel rounded-xl overflow-hidden shadow-2xl">
  <div class="overflow-x-auto">
    <table class="w-full text-left border-collapse">
      <thead>
        <tr class="bg-surface-container border-b border-outline-variant">
          <th class="p-md text-xs font-bold text-outline tracking-wider uppercase w-12 text-center"
          ></th>
          <th class="p-md text-xs font-bold text-outline tracking-wider uppercase">Hostname</th>
          <th class="p-md text-xs font-bold text-outline tracking-wider uppercase">Backend Proxy</th
          >
          <th class="p-md text-xs font-bold text-outline tracking-wider uppercase">SSL Status</th>
          <th class="p-md text-xs font-bold text-outline tracking-wider uppercase"
            >Max Request Body</th
          >
          <th class="p-md text-xs font-bold text-outline tracking-wider uppercase"
            >Security Profile</th
          >
          <th class="p-md text-xs font-bold text-outline tracking-wider uppercase text-right"
            >Actions</th
          >
        </tr>
      </thead>
      <tbody class="font-body-sm">
        {#each filteredVhosts as host, i}
          <!-- Standard Row -->
          <tr
            class="border-b border-outline-variant/30 hover:bg-surface-container-high transition-colors group cursor-pointer"
            on:click={() => toggleDetails(host.server_name)}
          >
            <td class="p-md text-center">
              <span
                class="material-symbols-outlined text-outline transition-transform duration-300 inline-block {expandedHosts[
                  host.server_name
                ]
                  ? 'rotate-180 text-primary'
                  : ''}"
              >
                expand_more
              </span>
            </td>
            <td class="p-md">
              <div class="flex flex-col">
                <span class="font-bold text-primary">{host.server_name}</span>
                <span class="text-[11px] text-outline font-mono">Rate Limit: {host.rate_limit}</span
                >
              </div>
            </td>
            <td class="p-md">
              <div class="flex items-center">
                <span class="w-2 h-2 rounded-full bg-primary shadow-[0_0_8px_#00d4ff]"></span>
                <span class="font-mono text-xs">{host.upstream}</span>
              </div>
            </td>
            <td class="p-md">
              {#if host.ssl === "Disabled"}
                <span
                  class="px-2.5 py-1 text-xs font-semibold rounded-full text-amber-400 bg-amber-400/10 border border-amber-400/20 inline-block font-mono"
                >
                  Disabled
                </span>
              {:else}
                <span
                  class="px-2.5 py-1 text-xs font-semibold rounded-full text-emerald-400 bg-emerald-400/10 border border-emerald-400/20 inline-flex items-center gap-1 font-mono"
                >
                  <span class="material-symbols-outlined text-[12px]">verified_user</span>
                  {host.ssl}
                </span>
              {/if}
            </td>
            <td class="p-md">
              <span class="font-mono text-xs">{host.max_body}</span>
            </td>
            <td class="p-md">
              <div class="flex flex-wrap gap-1">
                {#each host.rules as rule}
                  <span
                    class="px-2 py-0.5 text-[10px] font-semibold rounded-full text-red-400 bg-red-400/10 border border-red-400/20 uppercase font-mono"
                  >
                    {rule.replace("-*", "")}
                  </span>
                {:else}
                  <span class="text-xs text-on-surface-variant font-mono">None</span>
                {/each}
                {#if host.blocked_countries.length > 0}
                  <span
                    class="px-2.5 py-1 bg-amber-400/10 border border-amber-400/20 text-amber-400 text-[10px] font-bold rounded-full font-mono uppercase"
                  >
                    {host.geoblock_type === "Allowlist" ? "ALLOW" : "BLOCK"}: {host.blocked_countries.join(
                      ",",
                    )}
                  </span>
                {/if}
              </div>
            </td>
            <td class="p-md text-right">
              <div
                class="flex justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
              >
                <button
                  on:click={(e) => openEditModal(i, e)}
                  class="p-1.5 hover:bg-surface-container-highest rounded text-on-surface-variant hover:text-primary cursor-pointer bg-transparent border-none"
                  title="Edit VHost"
                >
                  <span class="material-symbols-outlined text-[18px]">edit</span>
                </button>
                <button
                  on:click={(e) => duplicateVhost(i, e)}
                  class="p-1.5 hover:bg-surface-container-highest rounded text-on-surface-variant hover:text-primary cursor-pointer bg-transparent border-none"
                  title="Duplicate VHost"
                >
                  <span class="material-symbols-outlined text-[18px]">content_copy</span>
                </button>
                <button
                  on:click={(e) => handleDeleteVhost(i, e)}
                  class="p-1.5 hover:bg-surface-container-highest rounded text-on-surface-variant hover:text-error cursor-pointer bg-transparent border-none"
                  title="Delete VHost"
                >
                  <span class="material-symbols-outlined text-[18px]">delete</span>
                </button>
              </div>
            </td>
          </tr>

          <!-- Expanded Row Details -->
          {#if expandedHosts[host.server_name]}
            <tr class="bg-surface-container-lowest/50">
              <td class="p-0" colspan="7">
                <div class="p-lg grid grid-cols-3 gap-lg border-b border-outline-variant">
                  <div class="space-y-3">
                    <p class="text-xs font-bold text-outline uppercase tracking-widest">
                      Routing & Limits
                    </p>
                    <div class="font-mono text-xs space-y-1.5 text-on-surface-variant">
                      <div class="flex justify-between border-b border-outline-variant/20 pb-1">
                        <span>Max Body Size</span>
                        <span class="text-primary">{host.max_body}</span>
                      </div>
                      <div class="flex justify-between border-b border-outline-variant/20 pb-1">
                        <span>Rate Limit</span>
                        <span class="text-on-surface">{host.rate_limit}</span>
                      </div>
                      <div class="flex justify-between pb-1">
                        <span>Custom Rules Count</span>
                        <span class="text-on-surface"
                          >{host.custom_rules ? host.custom_rules.length : 0} rules</span
                        >
                      </div>
                    </div>
                  </div>

                  <div class="space-y-3">
                    <p class="text-xs font-bold text-outline uppercase tracking-widest">
                      SSL encryption
                    </p>
                    <div class="font-mono text-xs space-y-1.5 text-on-surface-variant">
                      <div class="flex justify-between border-b border-outline-variant/20 pb-1">
                        <span>SSL Mode</span>
                        <span class="text-on-surface">{host.ssl}</span>
                      </div>
                      <div class="flex justify-between border-b border-outline-variant/20 pb-1">
                        <span>Virtual Host Protocol</span>
                        <span class="text-on-surface"
                          >{host.ssl !== "Disabled" ? "HTTPS/TLS" : "HTTP/Clear"}</span
                        >
                      </div>
                    </div>
                  </div>

                  <div class="space-y-3">
                    <p class="text-xs font-bold text-outline uppercase tracking-widest">
                      Geoblocking ({host.geoblock_type})
                    </p>
                    <div class="flex flex-wrap gap-1.5 mt-2">
                      {#each host.blocked_countries as countryCode}
                        <span
                          class="px-2 py-1 bg-surface-container border border-outline-variant rounded text-xs flex items-center gap-1"
                        >
                          <span>{flags[countryCode] || "🌐"}</span>
                          <span class="font-mono font-bold text-on-surface">{countryCode}</span>
                        </span>
                      {:else}
                        {#if host.geoblock_type === "Allowlist"}
                          <span class="text-xs font-bold text-error"
                            >Lockdown: Blocks All Traffic</span
                          >
                        {:else}
                          <span class="text-xs font-bold text-primary"
                            >Open Access: No geoblocks active</span
                          >
                        {/if}
                      {/each}
                    </div>
                  </div>
                </div>
              </td>
            </tr>
          {/if}
        {:else}
          <tr>
            <td colspan="7" class="p-lg text-center text-on-surface-variant font-mono">
              No Virtual Hosts match your search query.
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  <!-- Footer counts -->
  <div
    class="bg-surface-container p-md flex justify-between items-center border-t border-outline-variant text-xs text-outline"
  >
    <p>Showing {filteredVhosts.length} of {vhosts.length} virtual hosts</p>
    <p>SSL Active: {totalCerts} endpoints</p>
  </div>
</div>

<!-- Metric Grid Footer (NOC Context) -->
<div class="grid grid-cols-4 gap-lg mt-lg">
  <div class="glass-panel p-lg rounded-xl flex items-center justify-between">
    <div>
      <p class="text-[10px] font-bold text-outline uppercase tracking-widest mb-1">Total Vhosts</p>
      <p class="text-metric-lg font-metric-lg text-primary">{vhosts.length}</p>
    </div>
    <span class="material-symbols-outlined text-primary/30 text-[32px]">dns</span>
  </div>
  <div class="glass-panel p-lg rounded-xl flex items-center justify-between">
    <div>
      <p class="text-[10px] font-bold text-outline uppercase tracking-widest mb-1">SSL Protected</p>
      <p class="text-metric-lg font-metric-lg text-on-surface">{totalCerts}</p>
    </div>
    <span class="material-symbols-outlined text-on-surface/30 text-[32px]">verified</span>
  </div>
  <div
    class="glass-panel p-lg rounded-xl flex items-center justify-between border-b-2 border-b-primary"
  >
    <div>
      <p class="text-[10px] font-bold text-outline uppercase tracking-widest mb-1">
        Avg Reliability
      </p>
      <p class="text-metric-lg font-metric-lg text-on-surface">
        100.0<span class="text-sm font-normal">%</span>
      </p>
    </div>
    <span class="material-symbols-outlined text-primary/30 text-[32px]">hub</span>
  </div>
  <div class="glass-panel p-lg rounded-xl flex items-center justify-between">
    <div>
      <p class="text-[10px] font-bold text-outline uppercase tracking-widest mb-1">
        Geoblocked Vhosts
      </p>
      <p class="text-metric-lg font-metric-lg text-error">
        {vhosts.filter((h) => h.blocked_countries.length > 0).length}
      </p>
    </div>
    <span class="material-symbols-outlined text-error/30 text-[32px]">gpp_maybe</span>
  </div>
</div>

<!-- Modal Form Overlay -->
<VirtualHostModal
  show={showModal}
  {isEditing}
  bind:serverName={newServerName}
  bind:upstream={newUpstream}
  bind:ssl={newSsl}
  bind:maxBody={newMaxBody}
  bind:rateLimit={newRateLimit}
  bind:selectedCategories
  bind:blockedCountries
  bind:geoblockType
  on:close={() => (showModal = false)}
  on:save={handleSaveVhost}
/>

<style>
  .glass-panel {
    background: #0d1117;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-top: 1px solid rgba(255, 255, 255, 0.12);
    position: relative;
  }
</style>
