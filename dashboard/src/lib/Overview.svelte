<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { stats, dbSize, logs } from './stores';
  import PageHeader from './components/PageHeader.svelte';
  import MetricCard from './components/MetricCard.svelte';
  import GlassPanel from './components/GlassPanel.svelte';

  export let controllerUrl = '';

  interface AgentNode {
    hostname: string;
    ip: string;
    os: string;
    status: 'online' | 'offline';
    uptime: string;
    cpu: number;
    ram: number;
    disk: number;
    network_interfaces: string[];
    discovered_services: {
      name: string;
      port: number;
      protocol: string;
      source: string;
    }[];
  }

  interface VHost {
    name: string;
    hosts: string[];
    backend: string;
    ssl: string;
    geoblock_type: string;
    blocked_countries: string[];
    custom_rules: any[];
    rules: any[];
  }

  let agents: AgentNode[] = [];
  let vhosts: VHost[] = [];
  let totalRulesToggled = 0;
  let activeVhostsCount = 0;
  let logLimitMb = 500;
  let reqsPerSec = 0;
  let blockedIps: string[] = [];

  let updateInterval: ReturnType<typeof setInterval>;
  let summaryInterval: ReturnType<typeof setInterval>;
  let lastTotalRequests = 0;

  async function fetchSystemSummary() {
    try {
      const resVhosts = await fetch(`${controllerUrl}/api/v1/vhosts`);
      if (resVhosts.ok) {
        vhosts = await resVhosts.json();
        activeVhostsCount = vhosts.length;
        
        let rulesCount = 0;
        vhosts.forEach(v => {
          rulesCount += (v.rules ? v.rules.length : 0) + (v.custom_rules ? v.custom_rules.length : 0);
        });
        totalRulesToggled = rulesCount;
      }

      const resConfig = await fetch(`${controllerUrl}/api/v1/config`);
      if (resConfig.ok) {
        const cfg = await resConfig.json();
        logLimitMb = cfg.log_limit_mb;
      }

      const resBlocklist = await fetch(`${controllerUrl}/api/v1/reputation/blocklist`);
      if (resBlocklist.ok) {
        blockedIps = await resBlocklist.json();
      }

      const resAgents = await fetch(`${controllerUrl}/api/v1/agents`);
      if (resAgents.ok) {
        agents = await resAgents.json();
      }
    } catch (e) {
      console.error("Failed to fetch system summary:", e);
    }
  }

  function formatCount(num: number): string {
    if (num < 1000) return num.toString();
    if (num < 1000000) {
      return (num / 1000).toFixed(1).replace('.0', '') + 'k';
    }
    return (num / 1000000).toFixed(1).replace('.0', '') + 'M';
  }

  function formatTime(timestamp: string): string {
    try {
      if (timestamp.includes('T')) {
        return timestamp.split('T')[1].split('.')[0];
      }
      return timestamp;
    } catch {
      return timestamp;
    }
  }

  onMount(() => {
    fetchSystemSummary();
    summaryInterval = setInterval(fetchSystemSummary, 5000);
    
    updateInterval = setInterval(() => {
      const currentTotal = $stats.total_requests;
      if (lastTotalRequests > 0) {
        reqsPerSec = Math.max(0, Math.floor((currentTotal - lastTotalRequests) / 2.5));
      }
      lastTotalRequests = currentTotal;
    }, 2500);
  });

  onDestroy(() => {
    if (updateInterval) clearInterval(updateInterval);
    if (summaryInterval) clearInterval(summaryInterval);
  });
</script>

<div class="overview-panel flex flex-col gap-8">
  <!-- Header Section -->
  <PageHeader
    breadcrumbs={[{label: 'Aegis WAF'}, {label: 'Dashboard', active: true}]}
    title="Network Overview"
    subtitle="Real-time traffic telemetry and threat mitigation status."
  >
    <div slot="actions" class="flex gap-2">
      <div class="flex flex-col items-end">
        <span class="text-[10px] text-on-surface-variant uppercase font-bold">Sampling Rate</span>
        <span class="font-code-md text-code-md text-primary">1:1 (Real-time)</span>
      </div>
    </div>
  </PageHeader>

  <!-- Metric Grid -->
  <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
    <MetricCard
      label="Total Requests"
      value={formatCount($stats.total_requests)}
      subtext="({reqsPerSec} req/sec)"
      icon="dynamic_feed"
      colorClass="text-primary"
      progress={100}
      extraClass="cyan-glow"
    />

    <MetricCard
      label="Threats Blocked"
      value={formatCount($stats.blocked)}
      subtext={$stats.total_requests > 0 ? `(${(($stats.blocked / $stats.total_requests) * 100).toFixed(2)}%)` : ''}
      icon="gpp_maybe"
      colorClass="text-secondary"
      progress={$stats.total_requests > 0 ? ($stats.blocked / $stats.total_requests) * 100 : 0}
    />

    <MetricCard
      label="Rate Limited"
      value={formatCount($stats.rate_limited)}
      subtext={$stats.total_requests > 0 ? `(${(($stats.rate_limited / $stats.total_requests) * 100).toFixed(2)}%)` : ''}
      icon="speed"
      colorClass="text-tertiary"
      progress={$stats.total_requests > 0 ? ($stats.rate_limited / $stats.total_requests) * 100 : 0}
    />
  </div>

  <!-- Content Bento Grid -->
  <div class="grid grid-cols-12 gap-6">
    <!-- Agent Nodes (Live Health) -->
    <section class="col-span-12 lg:col-span-4 glass-panel rounded-xl overflow-hidden flex flex-col">
      <div class="px-4 py-4 border-b border-outline-variant flex justify-between items-center bg-surface-container-low">
        <h4 class="text-body-sm font-bold flex items-center gap-2 text-on-surface">
          <span class="material-symbols-outlined text-[18px]">dns</span>
          Agent Nodes
        </h4>
        <span class="text-[10px] font-code-md text-on-surface-variant">Active: {agents.filter(a => a.status === 'online').length}/{agents.length}</span>
      </div>

      <div class="p-4 space-y-4 flex-1 overflow-y-auto">
        {#if agents.length === 0}
          <div class="text-center py-8 text-on-surface-variant font-code-md text-xs">
            No WAF agents connected.<br/>
            Run the install command on your agent server:
            <div class="mt-2 p-2 bg-surface-container-lowest border border-outline-variant/30 rounded text-left overflow-x-auto text-[10px] whitespace-nowrap">
              <code>curl -sSL {controllerUrl}/install.sh | bash</code>
            </div>
          </div>
        {:else}
          {#each agents as agent}
            <div class="space-y-2 bg-surface-container-lowest/30 p-4 rounded-lg border border-outline-variant/20">
              <div class="flex justify-between items-center">
                <div class="flex items-center gap-2">
                  <span class="w-2 h-2 rounded-full {agent.status === 'online' ? 'bg-primary pulse-dot' : 'bg-secondary'}"></span>
                  <span class="text-xs font-bold text-on-surface">{agent.hostname}</span>
                  <span class="text-[10px] font-mono text-on-surface-variant">({agent.ip})</span>
                </div>
                <span class="text-[9px] font-mono bg-surface-container px-2 py-1 rounded text-on-surface-variant uppercase">{agent.os}</span>
              </div>

              <!-- Metrics -->
              <div class="space-y-1">
                <div class="flex justify-between text-[11px] font-code-md uppercase">
                  <span class="text-primary">{agent.hostname}</span>
                  <span class="text-on-surface-variant font-mono">{Math.round(agent.cpu)}% CPU</span>
                </div>
                <!-- CPU bar -->
                <div class="h-1.5 bg-surface-container rounded-full overflow-hidden flex">
                  <div class="h-full {agent.cpu > 80 ? 'bg-error' : 'bg-primary'}" style="width: {agent.cpu}%"></div>
                </div>
                <!-- RAM bar -->
                <div class="h-1 bg-surface-container rounded-full overflow-hidden flex">
                  <div class="h-full bg-primary/40" style="width: {agent.ram}%"></div>
                </div>
              </div>

              <div class="text-[9px] font-code-md text-on-surface-variant flex justify-between pt-2">
                <span>Uptime: {agent.uptime}</span>
                {#if agent.network_interfaces && agent.network_interfaces.length > 0}
                  <span>Interface: {agent.network_interfaces[0]}</span>
                {/if}
              </div>
            </div>
          {/each}
        {/if}
      </div>
    </section>

    <!-- Active VHosts Table -->
    <section class="col-span-12 lg:col-span-8 glass-panel rounded-xl overflow-hidden flex flex-col">
      <div class="px-4 py-4 border-b border-outline-variant flex justify-between items-center bg-surface-container-low">
        <h4 class="text-body-sm font-bold flex items-center gap-2 text-on-surface">
          <span class="material-symbols-outlined text-[18px]">public</span>
          Active VHosts
        </h4>
        <span class="text-[10px] font-code-md text-on-surface-variant">Active Routers: {vhosts.length}</span>
      </div>

      <div class="overflow-x-auto flex-1">
        <table class="w-full text-left font-body-sm text-body-sm">
          <thead class="bg-surface-container text-on-surface-variant text-[11px] uppercase font-bold">
            <tr>
              <th class="px-4 py-4">VHost Name</th>
              <th class="px-4 py-4">Backend Address</th>
              <th class="px-4 py-4">SSL Status</th>
              <th class="px-4 py-4">Rules</th>
              <th class="px-4 py-4 text-right">Geo Lock</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-outline-variant/30">
            {#each vhosts as host}
              <tr class="hover:bg-surface-container-low/50 transition-colors">
                <td class="px-4 py-4 font-bold text-on-surface font-mono">{host.hosts[0]}</td>
                <td class="px-4 py-4 font-code-md text-on-surface-variant">{host.backend}</td>
                <td class="px-4 py-4">
                  <div class="flex items-center gap-2">
                    {#if host.ssl !== 'Disabled'}
                      <span class="material-symbols-outlined text-[14px] text-primary" style="font-variation-settings: 'FILL' 1;">verified_user</span>
                      <span class="text-[11px] uppercase font-bold text-primary">{host.ssl}</span>
                    {:else}
                      <span class="material-symbols-outlined text-[14px] text-on-surface-variant">lock_open</span>
                      <span class="text-[11px] uppercase font-bold text-on-surface-variant">Disabled</span>
                    {/if}
                  </div>
                </td>
                <td class="px-4 py-4 font-code-md text-on-surface-variant">{(host.rules ? host.rules.length : 0) + (host.custom_rules ? host.custom_rules.length : 0)} rules</td>
                <td class="px-4 py-4 text-right">
                  {#if host.blocked_countries && host.blocked_countries.length > 0}
                    <span class="text-[10px] font-bold text-secondary uppercase bg-secondary-container/10 border border-secondary/20 px-2 py-1 rounded">
                      🔒 {host.geoblock_type} ({host.blocked_countries.length})
                    </span>
                  {:else}
                    <span class="text-[10px] font-bold text-primary uppercase bg-primary-container/10 border border-primary/20 px-2 py-1 rounded">
                      🔓 Open
                    </span>
                  {/if}
                </td>
              </tr>
            {:else}
              <tr>
                <td colspan="5" class="px-4 py-4 text-center text-on-surface-variant font-code-md col-span-5">No Virtual Hosts configured</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <!-- Security Event Log (Live Stream) -->
  <section class="glass-panel rounded-xl overflow-hidden">
    <div class="px-4 py-4 border-b border-outline-variant flex justify-between items-center bg-surface-container-low">
      <h4 class="text-body-sm font-bold flex items-center gap-2 text-on-surface">
        <span class="material-symbols-outlined text-[18px]">terminal</span>
        Security Event Log (Live Stream)
      </h4>
      <div class="flex gap-4 items-center">
        <div class="flex items-center gap-2">
          <span class="w-1.5 h-1.5 rounded-full bg-primary pulse-dot"></span>
          <span class="text-[10px] font-code-md uppercase text-primary">Connected</span>
        </div>
        <span class="text-[10px] font-code-md text-on-surface-variant">DB Size: {$dbSize}</span>
      </div>
    </div>
    
    <div class="p-4 font-code-md text-code-md h-48 overflow-y-auto terminal-scroll bg-surface-container-lowest" id="event-log">
      {#if $logs.length === 0}
        <div class="text-on-surface-variant text-center py-12 text-xs italic">
          Waiting for security event activity...
        </div>
      {:else}
        {#each $logs.slice(0, 50) as log}
          <div class="flex gap-4 {log.action === 'ALLOW' || log.action === 'PASS' ? 'opacity-70' : 'opacity-100'} mb-2 leading-tight">
            <span class="text-on-surface-variant shrink-0">[{formatTime(log.timestamp)}]</span>
            <span class="shrink-0 font-bold {log.action === 'ALLOW' || log.action === 'PASS' ? 'text-primary' : log.action === 'BLOCK' ? 'text-secondary' : 'text-tertiary'}">{log.action}</span>
            <span class="text-on-surface truncate">
              {log.method} <span class="text-on-surface-variant">{log.path}</span> - <span class="font-bold">{log.client_ip}</span> 
              {#if log.reason}
                <span class="text-on-surface-variant">({log.reason})</span>
              {/if}
            </span>
          </div>
        {/each}
      {/if}
    </div>
  </section>
</div>
