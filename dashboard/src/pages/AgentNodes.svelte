<script lang="ts">
  import { Server, Cpu, HardDrive, MemoryStick, Activity, Clock } from "lucide-svelte";
  import { agents } from "../lib/stores";
  import Card from "../components/ui/Card.svelte";
  import Badge from "../components/ui/Badge.svelte";
</script>

<div class="space-y-6 max-h-full overflow-y-auto pr-1">
  <div>
    <h1 class="text-2xl font-bold tracking-tight text-white flex items-center gap-2 md:text-3xl">
      <Server class="text-accent-blue" /> WAF Agent Nodes
    </h1>
    <p class="text-text-secondary text-sm mt-1">
      Detailed hardware telemetry, connection status, and service discovery network metrics for all proxy agents.
    </p>
  </div>

  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
    {#each $agents as node}
      <Card className="flex flex-col border-border-muted" interactive={true}>
        <!-- Card Header -->
        <div class="flex items-start justify-between border-b border-border-muted/80 pb-4 mb-4">
          <div>
            <h3 class="text-base font-bold text-white flex items-center gap-2">
              <Server size={16} class="text-accent-blue" />
              <span>{node.hostname}</span>
            </h3>
            <p class="text-xs font-mono text-text-muted mt-1">{node.ip}</p>
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
          <div class="bg-slate-950/40 p-3.5 rounded-xl border border-border-muted/60 shadow-inner">
            <div class="flex items-center gap-2 text-text-secondary mb-2">
              <Cpu size={14} />
              <span class="text-[10px] font-bold uppercase tracking-wider">CPU Usage</span>
            </div>
            <div class="text-lg font-mono font-bold text-white">
              {node.cpu.toFixed(1)}%
            </div>
            <div class="w-full bg-slate-900 h-1.5 mt-2 rounded-full overflow-hidden">
              <div
                class={`h-full rounded-full transition-all duration-500 ${node.cpu > 80 ? 'bg-error' : node.cpu > 50 ? 'bg-warning' : 'bg-accent-blue'}`}
                style="width: {node.cpu}%"
              ></div>
            </div>
          </div>

          <!-- Memory -->
          <div class="bg-slate-950/40 p-3.5 rounded-xl border border-border-muted/60 shadow-inner">
            <div class="flex items-center gap-2 text-text-secondary mb-2">
              <MemoryStick size={14} />
              <span class="text-[10px] font-bold uppercase tracking-wider">RAM Usage</span>
            </div>
            <div class="text-lg font-mono font-bold text-white">
              {node.ram.toFixed(1)}%
            </div>
            <div class="w-full bg-slate-900 h-1.5 mt-2 rounded-full overflow-hidden">
              <div
                class={`h-full rounded-full transition-all duration-500 ${node.ram > 80 ? 'bg-error' : node.ram > 50 ? 'bg-warning' : 'bg-success'}`}
                style="width: {node.ram}%"
              ></div>
            </div>
          </div>

          <!-- Disk -->
          <div class="bg-slate-950/40 p-3.5 rounded-xl border border-border-muted/60 shadow-inner">
            <div class="flex items-center gap-2 text-text-secondary mb-2">
              <HardDrive size={14} />
              <span class="text-[10px] font-bold uppercase tracking-wider">Disk</span>
            </div>
            <div class="text-sm font-mono font-bold text-white mt-1">
              {node.disk.toFixed(1)}% Used
            </div>
          </div>

          <!-- Uptime -->
          <div class="bg-slate-950/40 p-3.5 rounded-xl border border-border-muted/60 shadow-inner">
            <div class="flex items-center gap-2 text-text-secondary mb-2">
              <Clock size={14} />
              <span class="text-[10px] font-bold uppercase tracking-wider">Uptime</span>
            </div>
            <div class="text-sm font-mono font-bold text-white mt-1">
              {node.uptime}
            </div>
          </div>
        </div>

        <!-- Services and Network -->
        {#if node.discovered_services && node.discovered_services.length > 0}
          <div class="mt-4 border-t border-border-muted/80 pt-4">
            <h4 class="text-[10px] font-bold text-text-muted uppercase tracking-wider mb-2">
              Discovered Services
            </h4>
            <div class="flex flex-wrap gap-1.5">
              {#each node.discovered_services as svc}
                <Badge
                  variant="primary"
                  className="text-[10px] py-0.5"
                >
                  {svc.name} ({svc.port})
                </Badge>
              {/each}
            </div>
          </div>
        {/if}

        {#if node.network_interfaces && node.network_interfaces.length > 0}
          <div class="mt-4 border-t border-border-muted/80 pt-4">
            <h4 class="text-[10px] font-bold text-text-muted uppercase tracking-wider mb-2">
              Network Interfaces
            </h4>
            <div class="flex flex-wrap gap-1.5">
              {#each node.network_interfaces as net}
                <Badge
                  variant="neutral"
                  className="text-[10px] py-0.5"
                >
                  {net}
                </Badge>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Footer -->
        <div class="mt-4 pt-4 border-t border-border-muted/80 flex items-center justify-between">
          <div class="flex items-center gap-2 text-xs text-text-muted font-semibold">
            <Activity size={14} />
            <span>{node.os}</span>
          </div>
          <span class="text-[10px] font-bold font-mono text-text-muted/65 bg-slate-900/60 border border-border-muted/80 px-2 py-0.5 rounded-lg">v1.0.0</span>
        </div>
      </Card>
    {:else}
      <div class="col-span-full py-16 text-center text-text-muted flex flex-col items-center justify-center gap-3 select-none">
        <Server size={40} class="text-text-muted/40 animate-bounce" />
        <div>
          <p class="font-bold text-text-primary text-sm">No Connected Agent Nodes</p>
          <p class="text-xs text-text-muted mt-1 max-w-sm">Active proxy nodes will appear here once registered.</p>
        </div>
      </div>
    {/each}
  </div>
</div>
