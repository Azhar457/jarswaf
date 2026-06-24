<script lang="ts">
  import { Shield, Activity, Plus } from "lucide-svelte";
  import { rateLimits } from "../lib/stores";
  import Card from "../components/ui/Card.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import Badge from "../components/ui/Badge.svelte";
</script>

<div class="space-y-6">
  <div class="flex justify-between items-center">
    <div>
      <h1 class="text-2xl font-bold text-slate-100 tracking-tight">Rate Limiting</h1>
      <p class="text-slate-400 mt-1">
        Configure request thresholds to prevent abuse and DDoS attacks.
      </p>
    </div>
    <button
      class="bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors shadow-lg flex items-center gap-2"
    >
      <Plus size={18} />
      Add Policy
    </button>
  </div>

  <Card className="p-0 overflow-hidden">
    <DataTable columns={["Policy Name", "Target Path", "Limit", "Burst", "Status", "Actions"]}>
      {#each $rateLimits as policy}
        <tr class="hover:bg-slate-700/30 transition-colors">
          <td class="px-6 py-4 whitespace-nowrap">
            <div class="flex items-center gap-3">
              <div class="p-2 bg-slate-900 rounded-lg text-slate-400">
                <Activity size={16} />
              </div>
              <div>
                <div class="text-slate-200 font-medium">{policy.name}</div>
                <div
                  class="text-slate-500 text-xs mt-0.5 max-w-xs truncate"
                  title={policy.description}
                >
                  {policy.description}
                </div>
              </div>
            </div>
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-slate-400 font-mono text-sm">
            {policy.path}
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-slate-300 font-medium">
            {policy.limit}
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-slate-300">
            {policy.burst} reqs
          </td>
          <td class="px-6 py-4 whitespace-nowrap">
            <Badge variant="success">Active</Badge>
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-right">
            <button
              class="text-slate-400 hover:text-slate-100 transition-colors text-sm font-medium"
              >Edit</button
            >
          </td>
        </tr>
      {:else}
        <tr>
          <td colspan="6" class="px-6 py-8 text-center text-slate-500 italic"
            >No rate limiting policies defined.</td
          >
        </tr>
      {/each}
    </DataTable>
  </Card>
</div>
