<script lang="ts">
  import { Shield, Activity, Plus } from "lucide-svelte";
  import { rateLimits } from "../lib/stores";
  import Card from "../components/ui/Card.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import Badge from "../components/ui/Badge.svelte";
  import Button from "../components/ui/Button.svelte";
</script>

<div class="space-y-6 max-h-full overflow-y-auto pr-1">
  <div class="flex justify-between items-center gap-4">
    <div>
      <h1 class="text-2xl font-bold tracking-tight text-white md:text-3xl">Rate Limiting</h1>
      <p class="text-text-secondary text-sm mt-1">
        Configure request thresholds to prevent abuse, resource exhaustion, and DDoS attacks.
      </p>
    </div>
    <Button variant="primary" className="flex items-center gap-2 shrink-0">
      <Plus size={16} />
      <span>Add Policy</span>
    </Button>
  </div>

  <Card className="p-0 overflow-hidden">
    <DataTable columns={["Policy Name", "Target Path", "Limit", "Burst", "Status", "Actions"]}>
      {#each $rateLimits as policy}
        <tr class="hover:bg-slate-900/20 border-b border-border-muted/40 last:border-0 transition-colors">
          <td class="px-6 py-4 whitespace-nowrap">
            <div class="flex items-center gap-3">
              <div class="p-2 bg-slate-950/60 border border-border-muted/65 rounded-xl text-accent-blue shadow-inner">
                <Activity size={16} />
              </div>
              <div>
                <div class="text-text-primary font-bold text-sm">{policy.name}</div>
                <div
                  class="text-text-muted text-xs mt-1 max-w-xs truncate"
                  title={policy.description}
                >
                  {policy.description}
                </div>
              </div>
            </div>
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-text-secondary font-mono text-xs">
            {policy.path}
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-text-secondary font-semibold text-sm">
            {policy.limit}
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-text-secondary text-sm">
            {policy.burst} reqs
          </td>
          <td class="px-6 py-4 whitespace-nowrap">
            <Badge variant="success">Active</Badge>
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-right">
            <Button variant="ghost" className="text-xs py-1.5 px-3">Edit</Button>
          </td>
        </tr>
      {:else}
        <tr>
          <td colspan="6" class="px-6 py-12 text-center text-text-muted italic select-none">
            No rate limiting policies defined.
          </td>
        </tr>
      {/each}
    </DataTable>
  </Card>
</div>
