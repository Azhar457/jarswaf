<script lang="ts">
  import { ShieldAlert, Download, Trash2 } from "lucide-svelte";
  import { logs } from "../lib/stores";
  import Card from "../components/ui/Card.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import Badge from "../components/ui/Badge.svelte";

  function formatTime(timestamp: string) {
    const d = new Date(timestamp);
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
  }
</script>

<div class="space-y-6 h-full flex flex-col">
  <div class="flex justify-between items-center">
    <div>
      <h1 class="text-2xl font-bold text-slate-100 tracking-tight">Live Security Logs</h1>
      <p class="text-slate-400 mt-1">Real-time stream of all firewall events and requests.</p>
    </div>
    <div class="flex gap-3">
      <button
        class="bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium px-4 py-2 rounded-lg transition-colors border border-slate-700 flex items-center gap-2"
      >
        <Download size={16} />
        Export
      </button>
      <button
        class="bg-slate-800 hover:bg-slate-700 text-red-400 hover:text-red-300 text-sm font-medium px-4 py-2 rounded-lg transition-colors border border-slate-700 flex items-center gap-2"
      >
        <Trash2 size={16} />
        Clear
      </button>
    </div>
  </div>

  <Card className="p-0 flex-1 overflow-hidden flex flex-col min-h-[500px]">
    <div class="flex-1 overflow-y-auto custom-scrollbar">
      <DataTable columns={["Timestamp", "Client IP", "Method", "Path", "Action", "Reason"]}>
        {#each $logs as log}
          <tr class="hover:bg-slate-700/30 transition-colors">
            <td class="px-6 py-3 whitespace-nowrap text-slate-400 text-xs font-mono">
              {formatTime(log.timestamp)}
            </td>
            <td class="px-6 py-3 whitespace-nowrap text-slate-200 font-mono text-sm">
              {log.client_ip}
            </td>
            <td class="px-6 py-3 whitespace-nowrap text-slate-400 font-bold text-xs">
              {log.method}
            </td>
            <td
              class="px-6 py-3 whitespace-nowrap text-slate-300 text-sm max-w-[200px] truncate"
              title={log.path}
            >
              {log.path}
            </td>
            <td class="px-6 py-3 whitespace-nowrap">
              <Badge
                variant={log.action.toUpperCase() === "BLOCK"
                  ? "danger"
                  : log.action.toUpperCase() === "RATELIMIT"
                    ? "warning"
                    : "success"}
              >
                {log.action.toUpperCase()}
              </Badge>
            </td>
            <td
              class="px-6 py-3 text-slate-400 text-sm max-w-[300px] truncate"
              title={log.reason || "-"}
            >
              {log.reason || "-"}
            </td>
          </tr>
        {:else}
          <tr>
            <td colspan="6" class="px-6 py-8 text-center text-slate-500 italic"
              >No logs available.</td
            >
          </tr>
        {/each}
      </DataTable>
    </div>
  </Card>
</div>
