<script lang="ts">
  import { Shield, Activity, Plus, X, Trash2, Edit2 } from "lucide-svelte";
  import { rateLimits, token } from "../lib/stores";
  import Card from "../components/ui/Card.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import Badge from "../components/ui/Badge.svelte";
  import Button from "../components/ui/Button.svelte";
  import ConfirmationModal from "../components/ui/ConfirmationModal.svelte";
  import { toast } from "../lib/toast";

  const controllerUrl =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:8080";

  let showModal = false;
  let isEditing = false;
  let editIndex: number | null = null;

  // Form states
  let formName = "";
  let formPath = "";
  let formLimit = "";
  let formBurst = 10;
  let formDescription = "";

  // Delete modal state
  let showDeleteModal = false;
  let deleteIndex: number | null = null;

  function openAddModal() {
    isEditing = false;
    editIndex = null;
    formName = "";
    formPath = "";
    formLimit = "60 requests / minute";
    formBurst = 10;
    formDescription = "";
    showModal = true;
  }

  function openEditModal(index: number) {
    const policy = $rateLimits[index];
    isEditing = true;
    editIndex = index;
    formName = policy.name;
    formPath = policy.path;
    formLimit = policy.limit;
    formBurst = policy.burst;
    formDescription = policy.description || "";
    showModal = true;
  }

  function confirmDelete(index: number) {
    deleteIndex = index;
    showDeleteModal = true;
  }

  async function saveToServer(updatedList: any[]) {
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if ($token) {
        headers["Authorization"] = `Bearer ${$token}`;
      }
      const response = await fetch(`${controllerUrl}/api/v1/rate-limits`, {
        method: "POST",
        headers,
        body: JSON.stringify(updatedList),
      });
      if (!response.ok) throw new Error("Failed to save");
      rateLimits.set(updatedList);
      return true;
    } catch (e) {
      console.error(e);
      toast.error("Failed to save rate limit policy to backend.");
      return false;
    }
  }

  async function handleSubmit() {
    if (!formName.trim() || !formPath.trim() || !formLimit.trim()) {
      toast.error("Please fill in all required fields.");
      return;
    }

    const newPolicy = {
      name: formName.trim(),
      path: formPath.trim(),
      limit: formLimit.trim(),
      burst: Number(formBurst) || 0,
      description: formDescription.trim(),
    };

    let updatedList = [...$rateLimits];
    if (isEditing && editIndex !== null) {
      updatedList[editIndex] = newPolicy;
    } else {
      updatedList.push(newPolicy);
    }

    const success = await saveToServer(updatedList);
    if (success) {
      toast.success(isEditing ? "Rate limit policy updated." : "New rate limit policy created.");
      showModal = false;
    }
  }

  async function handleDelete() {
    if (deleteIndex === null) return;
    const updatedList = $rateLimits.filter((_, i) => i !== deleteIndex);
    const success = await saveToServer(updatedList);
    if (success) {
      toast.success("Rate limit policy deleted.");
      showDeleteModal = false;
      deleteIndex = null;
    }
  }
</script>

<div class="space-y-6 max-h-full overflow-y-auto pr-1">
  <div class="flex justify-between items-center gap-4">
    <div>
      <h1 class="text-2xl font-bold tracking-tight text-text-primary md:text-3xl">Rate Limiting</h1>
      <p class="text-text-secondary text-sm mt-1">
        Configure request thresholds to prevent abuse, resource exhaustion, and DDoS attacks.
      </p>
    </div>
    <Button on:click={openAddModal} variant="primary" className="flex items-center gap-2 shrink-0">
      <Plus size={16} />
      <span>Add Policy</span>
    </Button>
  </div>

  <Card className="p-0 overflow-hidden">
    <DataTable columns={["Policy Name", "Target Path", "Limit", "Burst", "Status", "Actions"]}>
      {#each $rateLimits as policy, i}
        <tr class="hover:bg-slate-900/20 border-b border-border-muted/40 last:border-0 transition-colors group">
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
            <div
              class="flex justify-end gap-2 opacity-100 md:opacity-0 md:group-hover:opacity-100 transition-opacity"
            >
              <Button
                variant="ghost"
                on:click={() => openEditModal(i)}
                className="p-1.5 text-text-muted hover:text-accent-blue rounded-xl"
                title="Edit"
              >
                <Edit2 size={15} />
              </Button>
              <Button
                variant="ghost"
                on:click={() => confirmDelete(i)}
                className="p-1.5 text-text-muted hover:text-error rounded-xl"
                title="Delete"
              >
                <Trash2 size={15} />
              </Button>
            </div>
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

<!-- Modal Form Overlay -->
{#if showModal}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm"
    on:click={(e) => { if (e.target === e.currentTarget) showModal = false; }}
  >
    <div
      class="bg-bg-secondary border border-border-muted w-full max-w-lg rounded-2xl shadow-premium overflow-hidden flex flex-col"
    >
      <!-- Header -->
      <div class="px-6 py-4 border-b border-border-muted flex justify-between items-center">
        <h3 class="text-lg font-bold text-text-primary">
          {isEditing ? "Edit Rate Limit Policy" : "Create Rate Limit Policy"}
        </h3>
        <button
          on:click={() => (showModal = false)}
          class="text-text-muted hover:text-text-primary transition-colors cursor-pointer bg-transparent border-none p-1.5 rounded-lg hover:bg-slate-900/60"
        >
          <X size={18} />
        </button>
      </div>

      <!-- Form Body -->
      <form on:submit|preventDefault={handleSubmit} class="p-6 space-y-4">
        <div class="space-y-1.5">
          <label for="policy_name" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Policy Name <span class="text-red-500">*</span>
          </label>
          <input
            id="policy_name"
            type="text"
            required
            placeholder="e.g. API Gateway Sync"
            bind:value={formName}
            class="input-field"
          />
        </div>

        <div class="space-y-1.5">
          <label for="policy_path" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Target URL Path Pattern <span class="text-red-500">*</span>
          </label>
          <input
            id="policy_path"
            type="text"
            required
            placeholder="e.g. /api/* or /login"
            bind:value={formPath}
            class="input-field font-mono"
          />
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div class="space-y-1.5">
            <label for="policy_limit" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Rate Limit String <span class="text-red-500">*</span>
            </label>
            <input
              id="policy_limit"
              type="text"
              required
              placeholder="e.g. 60 requests / minute"
              bind:value={formLimit}
              class="input-field"
            />
          </div>

          <div class="space-y-1.5">
            <label for="policy_burst" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Burst Token Capacity
            </label>
            <input
              id="policy_burst"
              type="number"
              min="0"
              placeholder="e.g. 10"
              bind:value={formBurst}
              class="input-field font-mono"
            />
          </div>
        </div>

        <div class="space-y-1.5">
          <label for="policy_desc" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Policy Description
          </label>
          <textarea
            id="policy_desc"
            placeholder="Describe what this rate limiting tier is enforced for..."
            bind:value={formDescription}
            class="input-field h-24 resize-none py-2"
          ></textarea>
        </div>

        <!-- Action Buttons -->
        <div class="pt-4 border-t border-border-muted flex justify-end gap-3">
          <Button
            variant="ghost"
            on:click={() => (showModal = false)}
            type="button"
          >
            Cancel
          </Button>
          <Button
            variant="primary"
            type="submit"
          >
            {isEditing ? "Save Changes" : "Create Policy"}
          </Button>
        </div>
      </form>
    </div>
  </div>
{/if}

<ConfirmationModal
  show={showDeleteModal}
  title="Delete Rate Limit Policy"
  message="Are you sure you want to delete this rate limit policy? Active nodes will stop throttling traffic on this path pattern immediately."
  confirmText="Delete"
  cancelText="Cancel"
  on:confirm={handleDelete}
  on:cancel={() => (showDeleteModal = false)}
/>
