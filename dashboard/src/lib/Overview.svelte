<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { stats, dbSize, logs, latestLog, type WafLog } from './stores';
  import { Terminal } from '@xterm/xterm';
  import { FitAddon } from '@xterm/addon-fit';
  import '@xterm/xterm/css/xterm.css';
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

  let terminalElement: HTMLDivElement;
  let term: Terminal | null = null;
  let fitAddon: FitAddon | null = null;
  let resizeObserver: ResizeObserver | null = null;
  let unsubscribeLogs: () => void;

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

  function writeLogToTerminal(log: WafLog) {
    if (!term) return;

    const timeStr = formatTime(log.timestamp);
    const action = (log.action || 'INFO').toUpperCase();
    const method = (log.method || 'GET').toUpperCase();
    const path = log.path || '/';
    const ip = log.client_ip || 'unknown';
    const reason = log.reason || '';

    let tagColor = '\x1b[1;32m'; // Bold green for standard ALLOWED/INFO
    if (action === 'BLOCK' || action === 'DENY') {
      tagColor = '\x1b[1;31m'; // Bold red
    } else if (action === 'LIMIT' || action === 'RATE_LIMIT') {
      tagColor = '\x1b[1;33m'; // Bold yellow
    }

    const actionTag = `${tagColor}[${action}]\x1b[0m`;
    const timeTag = `\x1b[90m[${timeStr}]\x1b[0m`;
    const methodTag = `\x1b[1;36m${method}\x1b[0m`;
    const pathTag = `\x1b[37m${path}\x1b[0m`;
    const ipTag = `\x1b[1;35m${ip}\x1b[0m`;
    const reasonTag = reason ? ` \x1b[33m(${reason})\x1b[0m` : '';

    term.writeln(`${actionTag} ${timeTag} ${methodTag} ${pathTag} — ${ipTag}${reasonTag}`);
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

    // Initialize Xterm.js Terminal
    term = new Terminal({
      theme: {
        background: '#040508',
        foreground: '#e2e2e9',
        cursor: '#a8e8ff',
        black: '#000000',
        red: '#ffb4ab',
        green: '#a8e8ff',
        yellow: '#ffd8a7',
        blue: '#3cd7ff',
        magenta: '#ffb2ba',
        cyan: '#b4ebff',
        white: '#e2e2e9',
      },
      fontFamily: 'JetBrains Mono, monospace',
      fontSize: 12,
      lineHeight: 1.4,
      cursorBlink: true,
      disableStdin: true,
      convertEol: true
    });

    fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalElement);
    
    // Fit the terminal to its DOM element
    setTimeout(() => {
      if (fitAddon) fitAddon.fit();
    }, 50);

    // Write a beautiful welcome banner
    term.writeln('\x1b[1;36mAegis WAF - Live Security Event Stream\x1b[0m');
    term.writeln('\x1b[90m================================================================================\x1b[0m');
    term.writeln('\x1b[32m[SYSTEM]\x1b[0m Terminal initialized. Streaming real-time security events...');
    term.writeln('');

    // Print existing logs history (reversing to show oldest first)
    const initialLogs = [...$logs].reverse();
    initialLogs.forEach(log => {
      if (term) writeLogToTerminal(log);
    });

    // Auto-fit terminal on resize
    resizeObserver = new ResizeObserver(() => {
      if (fitAddon) {
        try {
          fitAddon.fit();
        } catch (e) {
          // Fit error if element is hidden/detached
        }
      }
    });
    resizeObserver.observe(terminalElement);

    // Subscribe to latest log store for new events in real time
    unsubscribeLogs = latestLog.subscribe(log => {
      if (log && term) {
        writeLogToTerminal(log);
      }
    });
  });

  onDestroy(() => {
    if (updateInterval) clearInterval(updateInterval);
    if (summaryInterval) clearInterval(summaryInterval);
    if (unsubscribeLogs) unsubscribeLogs();
    if (resizeObserver) {
      resizeObserver.disconnect();
    }
    if (term) {
      term.dispose();
    }
  });
</script>

<div class="overview-panel flex flex-col gap-8">
  <!-- Header Section -->
  <PageHeader
    breadcrumbs={[{label: 'Aegis WAF'}, {label: 'Dashboard', active: true}]}
    title="Network Overview"
    subtitle="Real-time traffic telemetry and threat mitigation status."
  >
    <div slot="actions" class="flex ">
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
        <h4 class="text-body-sm font-bold flex items-center  text-on-surface">
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
                <div class="flex items-center">
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
        <h4 class="text-body-sm font-bold flex items-center  text-on-surface">
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
                  {#if host.ssl === 'Disabled'}
                    <span class="px-2.5 py-1 text-xs font-semibold rounded-full text-amber-400 bg-amber-400/10 border border-amber-400/20 inline-block font-mono">
                      Disabled
                    </span>
                  {:else}
                    <span class="px-2.5 py-1 text-xs font-semibold rounded-full text-emerald-400 bg-emerald-400/10 border border-emerald-400/20 inline-flex items-center gap-1 font-mono">
                      <span class="material-symbols-outlined text-[12px]">verified_user</span>
                      {host.ssl}
                    </span>
                  {/if}
                </td>
                <td class="px-4 py-4">
                  <div class="flex flex-wrap gap-1 max-w-[200px]">
                    {#each host.rules as rule}
                      <span class="px-2 py-0.5 text-[9px] font-semibold rounded-full text-red-400 bg-red-400/10 border border-red-400/20 uppercase font-mono">
                        {rule.replace('-*', '')}
                      </span>
                    {:else}
                      <span class="text-xs text-on-surface-variant font-mono">None</span>
                    {/each}
                  </div>
                </td>
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
      <h4 class="text-body-sm font-bold flex items-center  text-on-surface">
        <span class="material-symbols-outlined text-[18px]">terminal</span>
        Security Event Log (Live Stream)
      </h4>
      <div class="flex gap-4 items-center">
        <div class="flex items-center ">
          <span class="w-1.5 h-1.5 rounded-full bg-primary pulse-dot"></span>
          <span class="text-[10px] font-code-md uppercase text-primary">Connected</span>
        </div>
        <span class="text-[10px] font-code-md text-on-surface-variant">DB Size: {$dbSize}</span>
      </div>
    </div>
    
    <div 
      bind:this={terminalElement} 
      class="w-full h-72 bg-[#040508] p-3 rounded-lg border border-outline-variant/20 overflow-hidden"
    ></div>
  </section>
</div>
