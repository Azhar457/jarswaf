<script lang="ts">
  import { ShieldAlert, ShieldCheck, Activity, Server, AlertTriangle } from "lucide-svelte";
  import { stats, logs, vhostsCount, agents, connectionStatus } from "../lib/stores";
  import StatCard from "../components/ui/StatCard.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import Badge from "../components/ui/Badge.svelte";
  import LogViewer from "../components/ui/LogViewer.svelte";
  import Card from "../components/ui/Card.svelte";

  // Map WAF logs to the format LogViewer expects
  $: formattedLogs = $logs.slice(0, 50).map((log) => {
    const displayPath = log.path.length > 25 ? log.path.slice(0, 22) + "..." : log.path;
    return {
      level:
        log.action.toLowerCase() === "block"
          ? "ERROR"
          : log.action.toLowerCase() === "ratelimit"
            ? "WARN"
            : "INFO",
      message: `${log.client_ip} ${log.method} ${displayPath} - ${log.reason || log.action}`,
      timestamp: new Date(log.timestamp).toLocaleTimeString(),
    };
  }) as { level: "INFO" | "ERROR" | "WARN"; message: string; timestamp: string }[];

  $: isLoading = $connectionStatus === "connecting";
</script>

<div class="space-y-6 max-h-full overflow-y-auto pr-1">
  <!-- Header -->
  <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
    <div>
      <h1 class="text-2xl font-bold tracking-tight text-white md:text-3xl">SOC Dashboard</h1>
      <p class="text-text-secondary text-sm mt-1">Real-time threat monitoring, analytics, and service discovery node metrics.</p>
    </div>
    
    <!-- Connection status badge -->
    <div class="flex items-center gap-2 bg-slate-900/60 border border-border-muted/80 px-3 py-1.5 rounded-xl self-start md:self-auto">
      <div class={`w-2 h-2 rounded-full ${$connectionStatus === "online" ? "bg-success animate-pulse" : $connectionStatus === "connecting" ? "bg-warning animate-pulse" : "bg-error"}`}></div>
      <span class="text-xs font-semibold text-text-secondary uppercase tracking-wider">
        {$connectionStatus === "online" ? "Live Connected" : $connectionStatus === "connecting" ? "Connecting..." : "Disconnected"}
      </span>
    </div>
  </div>

  <!-- Stats Grid -->
  <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
    {#if isLoading}
      {#each Array(4) as _}
        <Card className="flex items-center p-6 h-28 animate-pulse">
          <div class="flex-1 space-y-3">
            <div class="h-4 bg-slate-800 rounded w-24"></div>
            <div class="h-6 bg-slate-800 rounded w-16"></div>
          </div>
          <div class="p-3 bg-slate-900/40 rounded-2xl w-12 h-12"></div>
        </Card>
      {/each}
    {:else}
      <StatCard
        title="Total Requests"
        value={$stats.total_requests.toLocaleString()}
        iconColor="text-blue-500"
      >
        <Activity slot="icon" size={20} />
      </StatCard>
      <StatCard
        title="Threats Blocked"
        value={$stats.blocked.toLocaleString()}
        iconColor="text-red-500"
      >
        <ShieldAlert slot="icon" size={20} />
      </StatCard>
      <StatCard
        title="Rate Limited"
        value={$stats.rate_limited.toLocaleString()}
        iconColor="text-amber-500"
      >
        <AlertTriangle slot="icon" size={20} />
      </StatCard>
      <StatCard title="Active VHosts" value={$vhostsCount} iconColor="text-emerald-500">
        <ShieldCheck slot="icon" size={20} />
      </StatCard>
    {/if}
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Agent Nodes -->
    <div class="lg:col-span-2 space-y-4">
      <div class="flex items-center justify-between">
        <h2 class="text-lg font-bold text-text-primary flex items-center gap-2">
          <Server size={18} class="text-accent-blue" />
          <span>Active WAF Agent Nodes</span>
        </h2>
        <span class="text-xs text-text-muted font-semibold bg-slate-900/60 border border-border-muted/80 px-2 py-0.5 rounded-lg">
          Nodes: {$agents.length}
        </span>
      </div>
      
      <Card className="p-0 overflow-hidden">
        {#if isLoading}
          <div class="p-8 space-y-4 animate-pulse">
            <div class="h-6 bg-slate-900/50 rounded w-1/3"></div>
            <div class="h-8 bg-slate-900/30 rounded w-full"></div>
            <div class="h-8 bg-slate-900/30 rounded w-full"></div>
            <div class="h-8 bg-slate-900/30 rounded w-full"></div>
          </div>
        {:else if $agents.length === 0}
          <div class="p-12 text-center text-text-muted flex flex-col items-center justify-center gap-3 select-none">
            <Server size={40} class="text-text-muted/40 animate-bounce" />
            <div>
              <p class="font-bold text-text-primary text-sm">No Active Agent Nodes Connected</p>
              <p class="text-xs text-text-muted mt-1 max-w-sm">Connect an agent node with your registration token to start protecting vhosts.</p>
            </div>
          </div>
        {:else}
          <DataTable columns={["Node ID", "IP Address", "Load", "Version", "Status"]}>
            {#each $agents as node}
              <tr class="hover:bg-slate-900/20 border-b border-border-muted/40 last:border-0 transition-colors">
                <td class="px-6 py-4 whitespace-nowrap text-text-primary font-bold text-sm">{node.hostname}</td>
                <td class="px-6 py-4 whitespace-nowrap text-text-secondary font-mono text-xs">{node.ip}</td>
                <td class="px-6 py-4 whitespace-nowrap text-text-secondary font-medium">
                  <div class="flex items-center gap-2">
                    <span class="w-16 text-xs">{node.cpu.toFixed(1)}% CPU</span>
                    <div class="w-20 bg-slate-900 rounded-full h-1.5 overflow-hidden">
                      <div class={`h-full ${node.cpu > 80 ? 'bg-error' : node.cpu > 50 ? 'bg-warning' : 'bg-success'}`} style={`width: ${node.cpu}%`}></div>
                    </div>
                  </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-text-muted text-xs font-semibold">{node.os}</td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <Badge
                    variant={node.status.toLowerCase() === "online"
                      ? "success"
                      : node.status.toLowerCase() === "warning"
                        ? "warning"
                        : "danger"}
                  >
                    {node.status}
                  </Badge>
                </td>
              </tr>
            {/each}
          </DataTable>
        {/if}
      </Card>
    </div>

    <!-- Security Event Logs -->
    <div class="space-y-4">
      <h2 class="text-lg font-bold text-text-primary">Live Security Logs</h2>
      <LogViewer logs={formattedLogs} loading={isLoading} />
    </div>
  </div>
</div>
