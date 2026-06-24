<script lang="ts">
  import { ShieldAlert, ShieldCheck, Activity, Server, AlertTriangle } from "lucide-svelte";
  import { stats, logs, vhostsCount, agents } from "../lib/stores";
  import StatCard from "../components/ui/StatCard.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import Badge from "../components/ui/Badge.svelte";
  import LogViewer from "../components/ui/LogViewer.svelte";
  import Card from "../components/ui/Card.svelte";

  // Map WAF logs to the format LogViewer expects
  $: formattedLogs = $logs.slice(0, 50).map((log) => ({
    level:
      log.action.toLowerCase() === "block"
        ? "ERROR"
        : log.action.toLowerCase() === "ratelimit"
          ? "WARN"
          : "INFO",
    message: `${log.client_ip} ${log.method} ${log.path} - ${log.reason || log.action}`,
    timestamp: new Date(log.timestamp).toLocaleTimeString(),
  })) as { level: "INFO" | "ERROR" | "WARN"; message: string; timestamp: string }[];
</script>

<div class="space-y-6">
  <!-- Header -->
  <div>
    <h1 class="text-2xl font-bold text-slate-100 tracking-tight">SOC Overview</h1>
    <p class="text-slate-400 mt-1">Real-time threat monitoring and system status.</p>
  </div>

  <!-- Stats Grid -->
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
    <StatCard
      title="Total Requests"
      value={$stats.total_requests.toLocaleString()}
      iconColor="text-blue-500"
    >
      <Activity slot="icon" size={24} />
    </StatCard>
    <StatCard
      title="Threats Blocked"
      value={$stats.blocked.toLocaleString()}
      iconColor="text-red-500"
    >
      <ShieldAlert slot="icon" size={24} />
    </StatCard>
    <StatCard
      title="Rate Limited"
      value={$stats.rate_limited.toLocaleString()}
      iconColor="text-amber-500"
    >
      <AlertTriangle slot="icon" size={24} />
    </StatCard>
    <StatCard title="Active VHosts" value={$vhostsCount} iconColor="text-emerald-500">
      <ShieldCheck slot="icon" size={24} />
    </StatCard>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Agent Nodes -->
    <div class="lg:col-span-2 space-y-4">
      <h2 class="text-lg font-semibold text-slate-200">Agent Nodes</h2>
      <Card className="p-0 overflow-hidden">
        <DataTable columns={["Node ID", "IP Address", "Load", "Version", "Status"]}>
          {#each $agents as node}
            <tr class="hover:bg-slate-700/30 transition-colors">
              <td class="px-6 py-4 whitespace-nowrap text-slate-300 font-medium">{node.hostname}</td
              >
              <td class="px-6 py-4 whitespace-nowrap text-slate-400 font-mono text-xs">{node.ip}</td
              >
              <td class="px-6 py-4 whitespace-nowrap text-slate-300">{node.cpu.toFixed(1)}% CPU</td>
              <td class="px-6 py-4 whitespace-nowrap text-slate-400">{node.os}</td>
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
      </Card>
    </div>

    <!-- Security Event Logs -->
    <div class="space-y-4">
      <h2 class="text-lg font-semibold text-slate-200">Security Event Log</h2>
      <LogViewer logs={formattedLogs} />
    </div>
  </div>
</div>
