<script lang="ts">
  import { onMount } from "svelte";
  import {
    Plus,
    Trash2,
    Edit2,
    Save,
    ToggleLeft,
    ToggleRight,
    ShieldAlert,
    ShieldCheck,
    RefreshCw,
  } from "lucide-svelte";
  import Card from "../components/ui/Card.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import Badge from "../components/ui/Badge.svelte";
  import ConfirmationModal from "../components/ui/ConfirmationModal.svelte";
  import Button from "../components/ui/Button.svelte";
  import Input from "../components/ui/Input.svelte";
  import { toast } from "../lib/toast";
  import { token } from "../lib/stores";

  const controllerUrl =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:8080";

  let activeSubTab: "allowlist" | "blacklist" = "allowlist";

  // Lists
  let allowlists: any[] = [];
  let blacklists: any[] = [];

  let loading = true;

  // Form State
  let showForm = false;
  let editingIndex: number | null = null;
  let ruleType: "allowlist" | "blacklist" = "allowlist";

  let formName = "";
  let formIps = "";
  let formPaths = "";
  let formBypassRules = ""; // Comma separated for allowlist only
  let formEnabled = true;

  let showDeleteModal = false;
  let deleteIndex: number | null = null;
  let deleteType: "allowlist" | "blacklist" = "allowlist";

  onMount(async () => {
    await fetchRules();
  });

  async function fetchRules() {
    loading = true;
    try {
      const headers: Record<string, string> = {};
      if ($token) {
        headers["Authorization"] = `Bearer ${$token}`;
      }

      const [allowRes, blackRes] = await Promise.all([
        fetch(`${controllerUrl}/api/v1/allowlists`, { headers }),
        fetch(`${controllerUrl}/api/v1/blacklists`, { headers }),
      ]);

      if (allowRes.status === 401 || blackRes.status === 401) {
        toast.error("Session expired. Please re-authenticate.");
        return;
      }

      if (allowRes.ok) {
        allowlists = await allowRes.json();
      }
      if (blackRes.ok) {
        blacklists = await blackRes.json();
      }
    } catch (err) {
      console.error(err);
      toast.error("Failed to fetch access control rules.");
    } finally {
      loading = false;
    }
  }

  async function saveAllowlists() {
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if ($token) {
        headers["Authorization"] = `Bearer ${$token}`;
      }
      const res = await fetch(`${controllerUrl}/api/v1/allowlists`, {
        method: "POST",
        headers,
        body: JSON.stringify(allowlists),
      });
      if (res.ok) {
        toast.success("Allowlist configuration saved.");
        return true;
      }
    } catch (e) {
      console.error(e);
    }
    toast.error("Failed to save Allowlist rules.");
    return false;
  }

  async function saveBlacklists() {
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if ($token) {
        headers["Authorization"] = `Bearer ${$token}`;
      }
      const res = await fetch(`${controllerUrl}/api/v1/blacklists`, {
        method: "POST",
        headers,
        body: JSON.stringify(blacklists),
      });
      if (res.ok) {
        toast.success("Blacklist configuration saved.");
        return true;
      }
    } catch (e) {
      console.error(e);
    }
    toast.error("Failed to save Blacklist rules.");
    return false;
  }

  function handleCreateRule(type: "allowlist" | "blacklist") {
    editingIndex = null;
    ruleType = type;
    formName = "";
    formIps = "";
    formPaths = "";
    formBypassRules = type === "allowlist" ? "*" : "";
    formEnabled = true;
    showForm = true;
  }

  function openEditForm(type: "allowlist" | "blacklist", index: number) {
    editingIndex = index;
    ruleType = type;
    const rule = type === "allowlist" ? allowlists[index] : blacklists[index];
    formName = rule.name;
    formIps = rule.ips ? rule.ips.join(", ") : "";
    formPaths = rule.paths ? rule.paths.join(", ") : "";
    formBypassRules = rule.bypass_rules ? rule.bypass_rules.join(", ") : "";
    formEnabled = rule.enabled;
    showForm = true;
  }

  async function handleSaveRule() {
    if (!formName) {
      toast.warning("Rule Name is required.");
      return;
    }
    if (!formIps && !formPaths) {
      toast.warning("Either IP Addresses or Path Patterns must be provided.");
      return;
    }

    const ipArray = formIps
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const pathArray = formPaths
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const bypassArray = formBypassRules
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    const rule = {
      name: formName,
      ips: ipArray,
      paths: pathArray,
      enabled: formEnabled,
      ...(ruleType === "allowlist" ? { bypass_rules: bypassArray } : {}),
    };

    if (ruleType === "allowlist") {
      if (editingIndex !== null) {
        allowlists[editingIndex] = rule;
      } else {
        allowlists = [...allowlists, rule];
      }
      await saveAllowlists();
    } else {
      if (editingIndex !== null) {
        blacklists[editingIndex] = rule;
      } else {
        blacklists = [...blacklists, rule];
      }
      await saveBlacklists();
    }

    showForm = false;
  }

  function confirmDelete(type: "allowlist" | "blacklist", index: number) {
    deleteType = type;
    deleteIndex = index;
    showDeleteModal = true;
  }

  async function executeDelete() {
    if (deleteIndex === null) return;
    if (deleteType === "allowlist") {
      allowlists = allowlists.filter((_, i) => i !== deleteIndex);
      await saveAllowlists();
    } else {
      blacklists = blacklists.filter((_, i) => i !== deleteIndex);
      await saveBlacklists();
    }
    showDeleteModal = false;
    deleteIndex = null;
  }

  async function toggleRule(type: "allowlist" | "blacklist", index: number) {
    if (type === "allowlist") {
      allowlists[index].enabled = !allowlists[index].enabled;
      allowlists = [...allowlists];
      await saveAllowlists();
    } else {
      blacklists[index].enabled = !blacklists[index].enabled;
      blacklists = [...blacklists];
      await saveBlacklists();
    }
  }

  function handleListInput(e: Event, callback: (arr: string[]) => void) {
    const target = e.target as HTMLInputElement;
    if (target) {
      callback(
        target.value
          .split(",")
          .map((s: string) => s.trim())
          .filter((s: string) => s.length > 0),
      );
    }
  }
</script>

<div class="space-y-6 max-h-full overflow-y-auto pr-1">
  <!-- Header -->
  <div class="flex justify-between items-center gap-4">
    <div>
      <h1 class="text-2xl font-bold tracking-tight text-white flex items-center gap-2 md:text-3xl">
        <ShieldCheck class="text-accent-blue" /> Access Control (ACL)
      </h1>
      <p class="text-text-secondary text-sm mt-1">
        Configure global allowlist rules (bypass WAF) and blacklist policies (explicit blocking).
      </p>
    </div>
    {#if !showForm}
      <Button
        on:click={() => handleCreateRule(activeSubTab)}
        variant="primary"
        className="flex items-center gap-2 shrink-0"
      >
        <Plus size={16} />
        <span>Add {activeSubTab === "allowlist" ? "Allowlist" : "Blacklist"}</span>
      </Button>
    {:else}
      <Button
        on:click={() => (showForm = false)}
        variant="secondary"
        className="flex items-center gap-2 shrink-0"
      >
        <span>Back to List</span>
      </Button>
    {/if}
  </div>

  <!-- Sub Tabs -->
  {#if !showForm}
    <div class="flex border-b border-border-muted/80 shrink-0">
      <button
        on:click={() => (activeSubTab = "allowlist")}
        class={`px-5 py-3 text-sm font-bold border-b-2 transition-all flex items-center gap-2 cursor-pointer bg-transparent ${activeSubTab === "allowlist" ? "border-accent-blue text-accent-blue" : "border-transparent text-text-muted hover:text-text-secondary"}`}
      >
        <ShieldCheck size={16} />
        <span>Allowlists (Exceptions)</span>
      </button>
      <button
        on:click={() => (activeSubTab = "blacklist")}
        class={`px-5 py-3 text-sm font-bold border-b-2 transition-all flex items-center gap-2 cursor-pointer bg-transparent ${activeSubTab === "blacklist" ? "border-accent-blue text-accent-blue" : "border-transparent text-text-muted hover:text-text-secondary"}`}
      >
        <ShieldAlert size={16} />
        <span>Blacklists (Blocking)</span>
      </button>
    </div>
  {/if}

  {#if showForm}
    <!-- Rule Form Editor -->
    <Card className="max-w-3xl border-border-muted">
      <div class="mb-6 border-b border-border-muted pb-4">
        <h2 class="text-lg font-bold text-white flex items-center gap-2">
          {#if ruleType === "allowlist"}
            <ShieldCheck class="text-success" size={20} />
          {:else}
            <ShieldAlert class="text-error" size={20} />
          {/if}
          <span>{editingIndex !== null ? "Edit Access Rule" : "Create New Access Rule"}</span>
        </h2>
        <p class="text-xs text-text-secondary mt-1">
          Define client IP subnets or path prefix matches to override WAF inspection logic.
        </p>
      </div>

      <div class="space-y-5">
        <div class="grid grid-cols-1 gap-5">
          <Input
            id="global_rule_name"
            label="Rule Name"
            bind:value={formName}
            placeholder="e.g. Office LAN / Nova CMS Bypass"
            required={true}
          />

          <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div class="space-y-1.5">
              <Input
                id="global_rule_ips"
                label="IP Addresses (Comma Separated)"
                bind:value={formIps}
                placeholder="e.g. 192.168.1.0/24, 10.0.0.5"
              />
              <p class="text-[11px] text-text-muted">
                Supports single IP or CIDR subnets. Leave blank if path-only.
              </p>
            </div>

            <div class="space-y-1.5">
              <Input
                id="global_rule_paths"
                label="Path Patterns (Comma Separated)"
                bind:value={formPaths}
                placeholder="e.g. /api/webhook/*, /nova/*"
              />
              <p class="text-[11px] text-text-muted">
                Supports wildcards (e.g. `*` prefix or suffix). Leave blank if IP-only.
              </p>
            </div>
          </div>

          {#if ruleType === "allowlist"}
            <div class="space-y-1.5 border-t border-border-muted/80 pt-4">
              <Input
                id="global_rule_bypass"
                label="Bypass Rules (Comma Separated)"
                bind:value={formBypassRules}
                placeholder="e.g. SQLI-*, XSS-*, or * to bypass all rules"
              />
              <p class="text-[11px] text-text-muted">
                Specify which rule IDs to bypass. Use `*` or leave empty to bypass the entire WAF engine.
              </p>
            </div>
          {/if}

          <div class="flex items-center gap-2.5 mt-2">
            <input
              type="checkbox"
              id="rule_enabled"
              bind:checked={formEnabled}
              class="w-4 h-4 rounded border-border-muted bg-slate-950 text-accent-blue focus:ring-accent-blue cursor-pointer"
            />
            <label
              for="rule_enabled"
              class="text-sm font-semibold text-text-secondary cursor-pointer select-none"
            >
              Rule Enabled
            </label>
          </div>
        </div>

        <div class="pt-6 border-t border-border-muted flex justify-end gap-3">
          <Button
            on:click={() => (showForm = false)}
            variant="ghost"
          >
            Cancel
          </Button>
          <Button
            on:click={handleSaveRule}
            variant="primary"
            className="flex items-center gap-2"
          >
            <Save size={16} />
            <span>Save Rule</span>
          </Button>
        </div>
      </div>
    </Card>
  {:else if loading}
    <div class="py-12 flex flex-col items-center justify-center text-text-muted gap-2.5">
      <RefreshCw class="animate-spin text-accent-blue" size={24} />
      <p class="text-sm font-semibold">Loading access control rules...</p>
    </div>
  {:else}
    <!-- Rules Table -->
    {#if activeSubTab === "allowlist"}
      <Card className="p-0 overflow-hidden">
        <DataTable
          columns={[
            "Rule Name",
            "Matched IPs",
            "Matched Paths",
            "Bypass Policy",
            "Status",
            "Actions",
          ]}
        >
          {#each allowlists as rule, i}
            <tr class="hover:bg-slate-900/20 border-b border-border-muted/40 last:border-0 transition-colors group {rule.enabled ? '' : 'opacity-45'}">
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="flex items-center gap-3">
                  <div
                    class="p-2 bg-success-bg rounded-xl text-success border border-success/15 shadow-inner"
                  >
                    <ShieldCheck size={16} />
                  </div>
                  <span class="text-text-primary font-bold text-sm">{rule.name}</span>
                </div>
              </td>
              <td class="px-6 py-4 text-text-secondary font-mono text-xs max-w-xs truncate">
                {rule.ips && rule.ips.length > 0 ? rule.ips.join(", ") : "Any IP"}
              </td>
              <td class="px-6 py-4 text-text-secondary font-mono text-xs max-w-xs truncate">
                {rule.paths && rule.paths.length > 0 ? rule.paths.join(", ") : "Any Path"}
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                {#if !rule.bypass_rules || rule.bypass_rules.length === 0 || rule.bypass_rules.includes("*")}
                  <Badge variant="success">Bypass All WAF</Badge>
                {:else}
                  <div class="flex flex-wrap gap-1">
                    {#each rule.bypass_rules as bypass}
                      <Badge variant="primary" className="text-[10px] py-0.5">{bypass}</Badge>
                    {/each}
                  </div>
                {/if}
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <button
                  on:click={() => toggleRule("allowlist", i)}
                  class="focus:outline-none border-none bg-transparent"
                  title={rule.enabled ? "Disable Rule" : "Enable Rule"}
                >
                  {#if rule.enabled}
                    <span
                      class="text-success hover:text-success/90 flex items-center gap-1.5 cursor-pointer"
                    >
                      <ToggleRight size={24} />
                      <span class="text-xs font-semibold uppercase tracking-wider">Active</span>
                    </span>
                  {:else}
                    <span
                      class="text-text-muted hover:text-text-secondary flex items-center gap-1.5 cursor-pointer"
                    >
                      <ToggleLeft size={24} />
                      <span class="text-xs font-semibold uppercase tracking-wider">Disabled</span>
                    </span>
                  {/if}
                </button>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-right">
                <div
                  class="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  <Button
                    variant="ghost"
                    on:click={() => openEditForm("allowlist", i)}
                    className="p-1.5 text-text-muted hover:text-accent-blue rounded-xl"
                    title="Edit"
                  >
                    <Edit2 size={15} />
                  </Button>
                  <Button
                    variant="ghost"
                    on:click={() => confirmDelete("allowlist", i)}
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
                No global allowlists defined. Click "Add Allowlist Rule" to create one.
              </td>
            </tr>
          {/each}
        </DataTable>
      </Card>
    {:else}
      <Card className="p-0 overflow-hidden">
        <DataTable columns={["Rule Name", "Matched IPs", "Matched Paths", "Status", "Actions"]}>
          {#each blacklists as rule, i}
            <tr class="hover:bg-slate-900/20 border-b border-border-muted/40 last:border-0 transition-colors group {rule.enabled ? '' : 'opacity-45'}">
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="flex items-center gap-3">
                  <div class="p-2 bg-error-bg rounded-xl text-error border border-error/15 shadow-inner">
                    <ShieldAlert size={16} />
                  </div>
                  <span class="text-text-primary font-bold text-sm">{rule.name}</span>
                </div>
              </td>
              <td class="px-6 py-4 text-text-secondary font-mono text-xs max-w-xs truncate">
                {rule.ips && rule.ips.length > 0 ? rule.ips.join(", ") : "Any IP"}
              </td>
              <td class="px-6 py-4 text-text-secondary font-mono text-xs max-w-xs truncate">
                {rule.paths && rule.paths.length > 0 ? rule.paths.join(", ") : "Any Path"}
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <button
                  on:click={() => toggleRule("blacklist", i)}
                  class="focus:outline-none border-none bg-transparent"
                  title={rule.enabled ? "Disable Rule" : "Enable Rule"}
                >
                  {#if rule.enabled}
                    <span
                      class="text-error hover:text-error/90 flex items-center gap-1.5 cursor-pointer"
                    >
                      <ToggleRight size={24} />
                      <span class="text-xs font-semibold uppercase tracking-wider">Blocking</span>
                    </span>
                  {:else}
                    <span
                      class="text-text-muted hover:text-text-secondary flex items-center gap-1.5 cursor-pointer"
                    >
                      <ToggleLeft size={24} />
                      <span class="text-xs font-semibold uppercase tracking-wider">Disabled</span>
                    </span>
                  {/if}
                </button>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-right">
                <div
                  class="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  <Button
                    variant="ghost"
                    on:click={() => openEditForm("blacklist", i)}
                    className="p-1.5 text-text-muted hover:text-accent-blue rounded-xl"
                    title="Edit"
                  >
                    <Edit2 size={15} />
                  </Button>
                  <Button
                    variant="ghost"
                    on:click={() => confirmDelete("blacklist", i)}
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
              <td colspan="5" class="px-6 py-12 text-center text-text-muted italic select-none">
                No global blacklists defined. Click "Add Blacklist Rule" to create one.
              </td>
            </tr>
          {/each}
        </DataTable>
      </Card>
    {/if}
  {/if}
</div>

<ConfirmationModal
  show={showDeleteModal}
  title="Delete Access Rule"
  message="Are you sure you want to permanently delete this rule? The exception or blocking policy will be immediately removed."
  confirmText="Delete Rule"
  on:confirm={executeDelete}
  on:cancel={() => {
    showDeleteModal = false;
    deleteIndex = null;
  }}
/>
