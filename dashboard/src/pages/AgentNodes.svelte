<script lang="ts">
  import { Server, Cpu, HardDrive, MemoryStick, Activity, Clock } from "lucide-svelte";
  import { agents } from "../lib/stores";
  import Card from "../components/ui/Card.svelte";
  import Badge from "../components/ui/Badge.svelte";
</script>

<div class="space-y-6">
  <div>
    <h1 class="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
      <Server class="text-blue-500" /> WAF Agent Nodes
    </h1>
    <p class="text-slate-400 mt-1">
      Detailed hardware telemetry and connection status for all reverse proxy agents.
    </p>
  </div>

  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
    {#each $agents as node}
      <Card className="flex flex-col border-slate-800 hover:border-slate-700 transition-colors">
        <!-- Card Header -->
        <div class="flex items-start justify-between border-b border-slate-800 pb-4 mb-4">
          <div>
            <h3 class="text-lg font-bold text-slate-200 flex items-center gap-2">
              <Server size={18} class="text-blue-400" />
              {node.hostname}
            </h3>
            <p class="text-xs font-mono text-slate-500 mt-1">{node.ip}</p>
          </div>
          <Badge
            variant={node.status.toLowerCase() === "online"
              ? "success"
              : node.status.toLowerCase() === "warning"
                ? "warning"
                : "danger"}
          >
            {node.status}
          </Badge>
        </div>

        <!-- Hardware Metrics Grid -->
        <div class="grid grid-cols-2 gap-4 flex-1">
          <!-- CPU -->
          <div class="bg-slate-900/50 p-3 rounded-lg border border-slate-800">
            <div class="flex items-center gap-2 text-slate-400 mb-2">
              <Cpu size={14} />
              <span class="text-[10px] font-bold uppercase tracking-wider">CPU Usage</span>
            </div>
            <div class="text-lg font-mono font-bold text-slate-200">
              {node.cpu.toFixed(1)}%
            </div>
            <div class="w-full bg-slate-800 h-1.5 mt-2 rounded-full overflow-hidden">
              <div
                class="bg-blue-500 h-full rounded-full transition-all duration-500"
                style="width: {node.cpu}%"
              ></div>
            </div>
          </div>

          <!-- Memory -->
          <div class="bg-slate-900/50 p-3 rounded-lg border border-slate-800">
            <div class="flex items-center gap-2 text-slate-400 mb-2">
              <MemoryStick size={14} />
              <span class="text-[10px] font-bold uppercase tracking-wider">RAM Usage</span>
            </div>
            <div class="text-lg font-mono font-bold text-slate-200">
              {node.ram.toFixed(1)}%
            </div>
            <div class="w-full bg-slate-800 h-1.5 mt-2 rounded-full overflow-hidden">
              <div
                class="bg-emerald-500 h-full rounded-full transition-all duration-500"
                style="width: {node.ram}%"
              ></div>
            </div>
          </div>

          <!-- Disk -->
          <div class="bg-slate-900/50 p-3 rounded-lg border border-slate-800">
            <div class="flex items-center gap-2 text-slate-400 mb-2">
              <HardDrive size={14} />
              <span class="text-[10px] font-bold uppercase tracking-wider">Disk</span>
            </div>
            <div class="text-sm font-mono font-bold text-slate-200 mt-2">
              {node.disk.toFixed(1)}% Used
            </div>
          </div>

          <!-- Uptime -->
          <div class="bg-slate-900/50 p-3 rounded-lg border border-slate-800">
            <div class="flex items-center gap-2 text-slate-400 mb-2">
              <Clock size={14} />
              <span class="text-[10px] font-bold uppercase tracking-wider">Uptime</span>
            </div>
            <div class="text-sm font-mono font-bold text-slate-200 mt-2">
              {node.uptime}
            </div>
          </div>
        </div>

        <!-- Services and Network -->
        {#if node.discovered_services && node.discovered_services.length > 0}
          <div class="mt-4 border-t border-slate-800 pt-4">
            <h4 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
              Discovered Services
            </h4>
            <div class="flex flex-wrap gap-2">
              {#each node.discovered_services as svc}
                <Badge
                  variant="primary"
                  className="text-[10px] bg-indigo-500/10 text-indigo-400 border-indigo-500/20"
                >
                  {svc.name} ({svc.port})
                </Badge>
              {/each}
            </div>
          </div>
        {/if}

        {#if node.network_interfaces && node.network_interfaces.length > 0}
          <div class="mt-4 border-t border-slate-800 pt-4">
            <h4 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
              Network Interfaces
            </h4>
            <div class="flex flex-wrap gap-2">
              {#each node.network_interfaces as net}
                <Badge
                  variant="neutral"
                  className="text-[10px] bg-slate-800 text-slate-400 border-slate-700"
                >
                  {net}
                </Badge>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Footer -->
        <div class="mt-4 pt-4 border-t border-slate-800 flex items-center justify-between">
          <div class="flex items-center gap-2 text-xs text-slate-500">
            <Activity size={14} />
            {node.os}
          </div>
          <span class="text-xs font-mono text-slate-600">v1.0.0</span>
        </div>
      </Card>
    {/each}
  </div>
</div>
