<script lang="ts">
  import { Plus, Globe, Trash2, Edit2, Shield, Activity, ArrowLeft, Save } from "lucide-svelte";
  import Card from "../components/ui/Card.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import Badge from "../components/ui/Badge.svelte";
  import ConfirmationModal from "../components/ui/ConfirmationModal.svelte";
  import { toast } from "../lib/toast";

  import { vhostsList } from "../lib/stores";

  const controllerUrl =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:8080";

  let showForm = false;
  let editingIndex: number | null = null;

  // Form State
  let formName = "";
  let formHosts = "";
  let formBackend = "";
  let formSsl = "Auto (Let's Encrypt)";
  let formMaxBody = "10MB";
  let formRateLimit = "100/m";

  let showDeleteModal = false;
  let vhostToDelete: number | null = null;

  async function saveToServer() {
    try {
      const response = await fetch(`${controllerUrl}/api/v1/vhosts`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify($vhostsList),
      });
      if (!response.ok) throw new Error("Failed to save");
      return true;
    } catch (e) {
      console.error(e);
      toast.error("Failed to save VHost configuration to backend.");
      return false;
    }
  }

  function openCreateForm() {
    editingIndex = null;
    formName = "";
    formHosts = "";
    formBackend = "http://127.0.0.1:8000";
    formSsl = "Auto (Let's Encrypt)";
    formMaxBody = "10MB";
    formRateLimit = "100/m";
    showForm = true;
  }

  function openEditForm(index: number) {
    editingIndex = index;
    const vhost = $vhostsList[index];
    formName = vhost.name;
    formHosts = vhost.hosts.join(", ");
    formBackend = vhost.backend;
    formSsl = vhost.ssl || "Auto (Let's Encrypt)";
    formMaxBody = vhost.max_body || "10MB";
    formRateLimit = vhost.rate_limit || "100/m";
    showForm = true;
  }

  async function handleSaveForm() {
    if (!formName || !formHosts || !formBackend) {
      toast.warning("Name, Domains, and Backend Proxy are required.");
      return;
    }

    const hostArray = formHosts
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    if (editingIndex !== null) {
      $vhostsList[editingIndex] = {
        ...$vhostsList[editingIndex],
        name: formName,
        hosts: hostArray,
        backend: formBackend,
        ssl: formSsl,
        max_body: formMaxBody,
        rate_limit: formRateLimit,
      };
      toast.success("Virtual Host updated successfully.");
    } else {
      $vhostsList.push({
        name: formName,
        hosts: hostArray,
        backend: formBackend,
        ssl: formSsl,
        max_body: formMaxBody,
        rate_limit: formRateLimit,
        rules: ["SQLI-*", "XSS-*", "LFI-*", "RFI-*", "CMDI-*"],
        custom_rules: [],
        blocked_countries: [],
        geoblock_type: "blacklist",
        rate_limit_tiers: [],
      });
      toast.success("New Virtual Host created successfully.");
    }

    vhostsList.set($vhostsList);
    await saveToServer();
    showForm = false;
  }

  function confirmDelete(index: number) {
    vhostToDelete = index;
    showDeleteModal = true;
  }

  async function executeDelete() {
    if (vhostToDelete === null) return;
    $vhostsList.splice(vhostToDelete, 1);
    vhostsList.set($vhostsList);
    toast.success("Virtual Host deleted successfully.");
    await saveToServer();
    showDeleteModal = false;
    vhostToDelete = null;
  }
</script>

<div class="space-y-6">
  <!-- Header -->
  <div class="flex justify-between items-center">
    <div>
      <h1 class="text-2xl font-bold text-slate-100 tracking-tight">Virtual Hosts</h1>
      <p class="text-slate-400 mt-1">Manage upstream proxies and security policies per domain.</p>
    </div>
    {#if showForm}
      <button
        on:click={() => (showForm = false)}
        class="bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors shadow-lg flex items-center gap-2 border border-slate-700"
      >
        <ArrowLeft size={18} />
        Back to List
      </button>
    {:else}
      <button
        on:click={openCreateForm}
        class="bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors shadow-lg flex items-center gap-2"
      >
        <Plus size={18} />
        Add VHost
      </button>
    {/if}
  </div>

  {#if showForm}
    <!-- VHost Form Editor -->
    <Card className="max-w-3xl border-slate-700 shadow-xl bg-slate-900/80">
      <div class="mb-6 border-b border-slate-800 pb-4">
        <h2 class="text-lg font-bold text-slate-200 flex items-center gap-2">
          <Globe class="text-blue-500" size={20} />
          {editingIndex !== null ? "Edit Virtual Host" : "Create New Virtual Host"}
        </h2>
        <p class="text-sm text-slate-500 mt-1">
          Configure your domain mapping and upstream server settings.
        </p>
      </div>

      <div class="space-y-5">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
          <div class="space-y-1.5">
            <label class="text-sm font-medium text-slate-300">VHost Name</label>
            <input
              type="text"
              bind:value={formName}
              placeholder="e.g. Main Production API"
              class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all placeholder:text-slate-600"
            />
          </div>

          <div class="space-y-1.5">
            <label class="text-sm font-medium text-slate-300">Domains (Comma Separated)</label>
            <input
              type="text"
              bind:value={formHosts}
              placeholder="e.g. api.example.com, example.com"
              class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all placeholder:text-slate-600"
            />
          </div>
        </div>

        <div class="space-y-1.5">
          <label class="text-sm font-medium text-slate-300">Backend Proxy Target</label>
          <input
            type="text"
            bind:value={formBackend}
            placeholder="http://127.0.0.1:8000"
            class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all font-mono placeholder:text-slate-600"
          />
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
          <div class="space-y-1.5">
            <label class="text-sm font-medium text-slate-300">SSL Configuration</label>
            <select
              bind:value={formSsl}
              class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 transition-all"
            >
              <option value="Auto (Let's Encrypt)">Auto (Let's Encrypt)</option>
              <option value="Custom Certificate">Custom Certificate</option>
              <option value="None (HTTP only)">None (HTTP only)</option>
            </select>
          </div>

          <div class="space-y-1.5">
            <label class="text-sm font-medium text-slate-300">Max Body Size</label>
            <select
              bind:value={formMaxBody}
              class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 transition-all"
            >
              <option value="1MB">1MB</option>
              <option value="10MB">10MB</option>
              <option value="50MB">50MB</option>
              <option value="100MB">100MB</option>
            </select>
          </div>

          <div class="space-y-1.5">
            <label class="text-sm font-medium text-slate-300">Default Rate Limit</label>
            <select
              bind:value={formRateLimit}
              class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 transition-all"
            >
              <option value="Disabled">Disabled</option>
              <option value="60/m">60 req/min</option>
              <option value="100/m">100 req/min</option>
              <option value="300/m">300 req/min</option>
              <option value="1000/m">1000 req/min</option>
            </select>
          </div>
        </div>

        <div class="pt-6 border-t border-slate-800 flex justify-end gap-3">
          <button
            on:click={() => (showForm = false)}
            class="px-5 py-2 text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            on:click={handleSaveForm}
            class="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-bold rounded-lg transition-colors shadow-lg shadow-blue-600/20 flex items-center gap-2"
          >
            <Save size={16} /> Save Configuration
          </button>
        </div>
      </div>
    </Card>
  {:else}
    <!-- VHost List Table -->
    <Card className="p-0 overflow-hidden border-slate-800">
      <DataTable
        columns={[
          "Domain",
          "Backend Proxy",
          "SSL Status",
          "Max Body",
          "Security Policies",
          "Actions",
        ]}
      >
        {#each $vhostsList as host, i}
          <tr class="hover:bg-slate-700/30 transition-colors group">
            <td class="px-6 py-4 whitespace-nowrap">
              <div class="flex items-center gap-3">
                <div
                  class="p-2 bg-slate-900 rounded-lg text-slate-400 group-hover:text-blue-400 transition-colors border border-slate-800"
                >
                  <Globe size={16} />
                </div>
                <div class="flex flex-col">
                  <span class="text-slate-200 font-bold">{host.name}</span>
                  <span class="text-slate-500 text-xs mt-0.5"
                    >{host.hosts.length > 0 ? host.hosts.join(", ") : "*"}</span
                  >
                </div>
              </div>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-slate-400 font-mono text-xs">
              {host.backend}
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
              <Badge
                variant={(host.ssl || "").toLowerCase().includes("auto")
                  ? "success"
                  : (host.ssl || "").toLowerCase().includes("expired")
                    ? "danger"
                    : "warning"}
              >
                {host.ssl || "None"}
              </Badge>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-slate-300 text-sm">
              {host.max_body || "10MB"}
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
              <div class="flex flex-wrap gap-1">
                {#if host.rules.length === 0}
                  <Badge variant="danger">Disabled</Badge>
                {:else}
                  {#each host.rules.slice(0, 2) as policy}
                    <Badge variant="primary" className="text-[10px] py-0.5">{policy}</Badge>
                  {/each}
                  {#if host.rules.length > 2}
                    <Badge variant="neutral" className="text-[10px] py-0.5"
                      >+{host.rules.length - 2}</Badge
                    >
                  {/if}
                {/if}
              </div>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-right">
              <div
                class="flex justify-end gap-3 opacity-0 group-hover:opacity-100 transition-opacity"
              >
                <button
                  on:click={() => openEditForm(i)}
                  class="text-slate-400 hover:text-blue-400 transition-colors p-1"
                  title="Edit"
                >
                  <Edit2 size={16} />
                </button>
                <button
                  on:click={() => confirmDelete(i)}
                  class="text-slate-400 hover:text-red-400 transition-colors p-1"
                  title="Delete"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </td>
          </tr>
        {:else}
          <tr>
            <td colspan="6" class="px-6 py-8 text-center text-slate-500 italic"
              >No Virtual Hosts configured. Click "Add VHost" to create one.</td
            >
          </tr>
        {/each}
      </DataTable>
    </Card>
  {/if}
</div>

<ConfirmationModal
  show={showDeleteModal}
  title="Delete Virtual Host"
  message="Are you sure you want to permanently delete this Virtual Host? All traffic targeting this domain will immediately return a 404 error."
  confirmText="Delete VHost"
  on:confirm={executeDelete}
  on:cancel={() => {
    showDeleteModal = false;
    vhostToDelete = null;
  }}
/>
