<script lang="ts">
  import { onMount } from "svelte";
  import { Plus, Trash2, Edit2, Shield, Activity, Save, ToggleLeft, ToggleRight, Check, X, ShieldAlert, ShieldCheck } from "lucide-svelte";
  import Card from "../components/ui/Card.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import Badge from "../components/ui/Badge.svelte";
  import ConfirmationModal from "../components/ui/ConfirmationModal.svelte";
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
        fetch(`${controllerUrl}/api/v1/blacklists`, { headers })
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
      throw new Error();
    } catch (e) {
      toast.error("Failed to save allowlists.");
      return false;
    }
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
      throw new Error();
    } catch (e) {
      toast.error("Failed to save blacklists.");
      return false;
    }
  }

  function openCreateForm(type: "allowlist" | "blacklist") {
    ruleType = type;
    editingIndex = null;
    formName = "";
    formIps = "";
    formPaths = "";
    formBypassRules = type === "allowlist" ? "*" : "";
    formEnabled = true;
    showForm = true;
  }

  function openEditForm(type: "allowlist" | "blacklist", index: number) {
    ruleType = type;
    editingIndex = index;
    const rule = type === "allowlist" ? allowlists[index] : blacklists[index];
    formName = rule.name;
    formIps = rule.ips ? rule.ips.join(", ") : "";
    formPaths = rule.paths ? rule.paths.join(", ") : "";
    formBypassRules = type === "allowlist" && rule.bypass_rules ? rule.bypass_rules.join(", ") : "";
    formEnabled = rule.enabled;
    showForm = true;
  }

  async function handleSaveRule() {
    if (!formName) {
      toast.warning("Rule Name is required.");
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

    if (ipArray.length === 0 && pathArray.length === 0) {
      toast.warning("At least one IP or Path pattern is required.");
      return;
    }

    if (ruleType === "allowlist") {
      const bypassArray = formBypassRules
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);

      const ruleObj = {
        name: formName,
        ips: ipArray,
        paths: pathArray,
        bypass_rules: bypassArray,
        enabled: formEnabled,
      };

      if (editingIndex !== null) {
        allowlists[editingIndex] = ruleObj;
      } else {
        allowlists.push(ruleObj);
      }
      allowlists = [...allowlists];
      await saveAllowlists();
    } else {
      const ruleObj = {
        name: formName,
        ips: ipArray,
        paths: pathArray,
        enabled: formEnabled,
      };

      if (editingIndex !== null) {
        blacklists[editingIndex] = ruleObj;
      } else {
        blacklists.push(ruleObj);
      }
      blacklists = [...blacklists];
      await saveBlacklists();
    }

    showForm = false;
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

  function confirmDelete(type: "allowlist" | "blacklist", index: number) {
    deleteType = type;
    deleteIndex = index;
    showDeleteModal = true;
  }

  async function executeDelete() {
    if (deleteIndex === null) return;
    if (deleteType === "allowlist") {
      allowlists.splice(deleteIndex, 1);
      allowlists = [...allowlists];
      await saveAllowlists();
    } else {
      blacklists.splice(deleteIndex, 1);
      blacklists = [...blacklists];
      await saveBlacklists();
    }
    showDeleteModal = false;
    deleteIndex = null;
  }
</script>

<div class="space-y-6">
  <!-- Header -->
  <div class="flex justify-between items-center">
    <div>
      <h1 class="text-2xl font-bold text-slate-100 tracking-tight">Access Control</h1>
      <p class="text-slate-400 mt-1">Configure global client IP and path exceptions (Allowlists & Blacklists).</p>
    </div>
    {#if showForm}
      <button
        on:click={() => (showForm = false)}
        class="bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors shadow-lg flex items-center gap-2 border border-slate-700 font-sans cursor-pointer"
      >
        Back to List
      </button>
    {:else}
      <button
        on:click={() => openCreateForm(activeSubTab)}
        class="bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors shadow-lg flex items-center gap-2 font-sans cursor-pointer"
      >
        <Plus size={18} />
        Add {activeSubTab === "allowlist" ? "Allowlist Rule" : "Blacklist Rule"}
      </button>
    {/if}
  </div>

  <!-- Sub Tabs -->
  {#if !showForm}
    <div class="flex border-b border-slate-800 gap-6">
      <button
        on:click={() => (activeSubTab = "allowlist")}
        class={`pb-3 text-sm font-bold border-b-2 transition-all flex items-center gap-2 cursor-pointer ${
          activeSubTab === "allowlist"
            ? "border-blue-500 text-blue-400"
            : "border-transparent text-slate-400 hover:text-slate-200"
        }`}
      >
        <ShieldCheck size={16} />
        Global Allowlist
      </button>
      <button
        on:click={() => (activeSubTab = "blacklist")}
        class={`pb-3 text-sm font-bold border-b-2 transition-all flex items-center gap-2 cursor-pointer ${
          activeSubTab === "blacklist"
            ? "border-blue-500 text-blue-400"
            : "border-transparent text-slate-400 hover:text-slate-200"
        }`}
      >
        <ShieldAlert size={16} />
        Global Blacklist
      </button>
    </div>
  {/if}

  {#if showForm}
    <!-- Rule Form Editor -->
    <Card className="max-w-3xl border-slate-700 shadow-xl bg-slate-900/80">
      <div class="mb-6 border-b border-slate-800 pb-4">
        <h2 class="text-lg font-bold text-slate-200 flex items-center gap-2">
          {#if ruleType === "allowlist"}
            <ShieldCheck class="text-emerald-500" size={20} />
          {:else}
            <ShieldAlert class="text-red-500" size={20} />
          {/if}
          {editingIndex !== null ? "Edit Rule" : "Create New Rule"} ({ruleType === "allowlist" ? "Allowlist" : "Blacklist"})
        </h2>
        <p class="text-sm text-slate-500 mt-1">
          Define matching patterns for client IPs and paths to apply exceptions.
        </p>
      </div>

      <div class="space-y-5">
        <div class="grid grid-cols-1 gap-5">
          <div class="space-y-1.5">
            <label for="global_rule_name" class="text-sm font-medium text-slate-300">Rule Name</label>
            <input
              id="global_rule_name"
              type="text"
              bind:value={formName}
              placeholder="e.g. Office LAN / Nova CMS Bypass"
              class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all placeholder:text-slate-600"
            />
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div class="space-y-1.5">
              <label for="global_rule_ips" class="text-sm font-medium text-slate-300">IP Addresses (Comma Separated)</label>
              <input
                id="global_rule_ips"
                type="text"
                bind:value={formIps}
                placeholder="e.g. 192.168.1.0/24, 10.0.0.5"
                class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all placeholder:text-slate-600"
              />
              <p class="text-xs text-slate-500">Supports single IP or CIDR subnets. Leave blank if path-only.</p>
            </div>

            <div class="space-y-1.5">
              <label for="global_rule_paths" class="text-sm font-medium text-slate-300">Path Patterns (Comma Separated)</label>
              <input
                id="global_rule_paths"
                type="text"
                bind:value={formPaths}
                placeholder="e.g. /api/webhook/*, /nova/*"
                class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all placeholder:text-slate-600"
              />
              <p class="text-xs text-slate-500">Supports wildcards (e.g. `*` prefix or suffix). Leave blank if IP-only.</p>
            </div>
          </div>

          {#if ruleType === "allowlist"}
            <div class="space-y-1.5 border-t border-slate-800 pt-4">
              <label for="global_rule_bypass" class="text-sm font-medium text-slate-300">Bypass Rules (Comma Separated)</label>
              <input
                id="global_rule_bypass"
                type="text"
                bind:value={formBypassRules}
                placeholder="e.g. SQLI-AST, XSS-*, or * to bypass all rules"
                class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all placeholder:text-slate-600"
              />
              <p class="text-xs text-slate-500">
                Specify which rule IDs to bypass. Use `*` or leave empty to bypass the entire WAF engine.
              </p>
            </div>
          {/if}

          <div class="flex items-center gap-2 mt-2">
            <input
              type="checkbox"
              id="rule_enabled"
              bind:checked={formEnabled}
              class="w-4 h-4 rounded border-slate-800 bg-slate-950 text-blue-600 focus:ring-blue-500 focus:ring-offset-slate-900 cursor-pointer"
            />
            <label for="rule_enabled" class="text-sm font-medium text-slate-300 cursor-pointer select-none">
              Rule Enabled
            </label>
          </div>
        </div>

        <div class="pt-6 border-t border-slate-800 flex justify-end gap-3 font-sans">
          <button
            on:click={() => (showForm = false)}
            class="px-5 py-2 text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
          >
            Cancel
          </button>
          <button
            on:click={handleSaveRule}
            class="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-bold rounded-lg transition-colors shadow-lg shadow-blue-600/20 flex items-center gap-2 cursor-pointer"
          >
            <Save size={16} /> Save Rule
          </button>
        </div>
      </div>
    </Card>
  {:else if loading}
    <div class="py-12 flex flex-col items-center justify-center text-slate-500">
      <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mb-3"></div>
      <p class="text-sm font-medium font-sans">Loading access control rules...</p>
    </div>
  {:else}
    <!-- Rules Table -->
    {#if activeSubTab === "allowlist"}
      <Card className="p-0 overflow-hidden border-slate-800">
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
            <tr class="hover:bg-slate-700/30 transition-colors group">
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="flex items-center gap-3">
                  <div class="p-2 bg-emerald-500/10 rounded-lg text-emerald-500 border border-emerald-500/20">
                    <ShieldCheck size={16} />
                  </div>
                  <span class="text-slate-200 font-bold">{rule.name}</span>
                </div>
              </td>
              <td class="px-6 py-4 text-slate-400 font-mono text-xs max-w-xs truncate">
                {rule.ips && rule.ips.length > 0 ? rule.ips.join(", ") : "Any IP"}
              </td>
              <td class="px-6 py-4 text-slate-400 font-mono text-xs max-w-xs truncate">
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
                  class="focus:outline-none"
                  title={rule.enabled ? "Disable Rule" : "Enable Rule"}
                >
                  {#if rule.enabled}
                    <span class="text-emerald-500 hover:text-emerald-400 flex items-center gap-1.5 cursor-pointer">
                      <ToggleRight size={24} />
                      <span class="text-xs font-semibold uppercase tracking-wider">Active</span>
                    </span>
                  {:else}
                    <span class="text-slate-500 hover:text-slate-400 flex items-center gap-1.5 cursor-pointer">
                      <ToggleLeft size={24} />
                      <span class="text-xs font-semibold uppercase tracking-wider">Disabled</span>
                    </span>
                  {/if}
                </button>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-right font-sans">
                <div class="flex justify-end gap-3 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    on:click={() => openEditForm("allowlist", i)}
                    class="text-slate-400 hover:text-blue-400 transition-colors p-1 cursor-pointer"
                    title="Edit"
                  >
                    <Edit2 size={16} />
                  </button>
                  <button
                    on:click={() => confirmDelete("allowlist", i)}
                    class="text-slate-400 hover:text-red-400 transition-colors p-1 cursor-pointer"
                    title="Delete"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </td>
            </tr>
          {:else}
            <tr>
              <td colspan="6" class="px-6 py-8 text-center text-slate-500 italic font-sans">
                No global allowlists defined. Click "Add Allowlist Rule" to create one.
              </td>
            </tr>
          {/each}
        </DataTable>
      </Card>
    {:else}
      <Card className="p-0 overflow-hidden border-slate-800">
        <DataTable
          columns={[
            "Rule Name",
            "Matched IPs",
            "Matched Paths",
            "Status",
            "Actions",
          ]}
        >
          {#each blacklists as rule, i}
            <tr class="hover:bg-slate-700/30 transition-colors group">
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="flex items-center gap-3">
                  <div class="p-2 bg-red-500/10 rounded-lg text-red-500 border border-red-500/20">
                    <ShieldAlert size={16} />
                  </div>
                  <span class="text-slate-200 font-bold">{rule.name}</span>
                </div>
              </td>
              <td class="px-6 py-4 text-slate-400 font-mono text-xs max-w-xs truncate">
                {rule.ips && rule.ips.length > 0 ? rule.ips.join(", ") : "Any IP"}
              </td>
              <td class="px-6 py-4 text-slate-400 font-mono text-xs max-w-xs truncate">
                {rule.paths && rule.paths.length > 0 ? rule.paths.join(", ") : "Any Path"}
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <button
                  on:click={() => toggleRule("blacklist", i)}
                  class="focus:outline-none"
                  title={rule.enabled ? "Disable Rule" : "Enable Rule"}
                >
                  {#if rule.enabled}
                    <span class="text-red-500 hover:text-red-400 flex items-center gap-1.5 cursor-pointer">
                      <ToggleRight size={24} />
                      <span class="text-xs font-semibold uppercase tracking-wider">Blocking</span>
                    </span>
                  {:else}
                    <span class="text-slate-500 hover:text-slate-400 flex items-center gap-1.5 cursor-pointer">
                      <ToggleLeft size={24} />
                      <span class="text-xs font-semibold uppercase tracking-wider">Disabled</span>
                    </span>
                  {/if}
                </button>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-right font-sans">
                <div class="flex justify-end gap-3 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    on:click={() => openEditForm("blacklist", i)}
                    class="text-slate-400 hover:text-blue-400 transition-colors p-1 cursor-pointer"
                    title="Edit"
                  >
                    <Edit2 size={16} />
                  </button>
                  <button
                    on:click={() => confirmDelete("blacklist", i)}
                    class="text-slate-400 hover:text-red-400 transition-colors p-1 cursor-pointer"
                    title="Delete"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </td>
            </tr>
          {:else}
            <tr>
              <td colspan="5" class="px-6 py-8 text-center text-slate-500 italic font-sans">
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
