<script lang="ts">
  import { Plus, Globe, Trash2, Edit2, Shield, Activity, ArrowLeft, Save } from "lucide-svelte";
  import Card from "../components/ui/Card.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import Badge from "../components/ui/Badge.svelte";
  import ConfirmationModal from "../components/ui/ConfirmationModal.svelte";
  import Button from "../components/ui/Button.svelte";
  import Input from "../components/ui/Input.svelte";
  import { toast } from "../lib/toast";

  import { vhostsList, token, agents } from "../lib/stores";

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
  let formIsDefault = false;

  let showDeleteModal = false;
  let vhostToDelete: number | null = null;

  // Compile unique active ports/services scanned by agents
  $: discoveredServices = $agents
    .flatMap((a) => a.discovered_services || [])
    .map((s) => ({
      label: `[${s.source}] ${s.name} (Port ${s.port})`,
      value: `http://127.0.0.1:${s.port}`,
    }))
    .filter((v, i, self) => self.findIndex((t) => t.value === v.value) === i);

  async function saveToServer() {
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if ($token) {
        headers["Authorization"] = `Bearer ${$token}`;
      }
      const response = await fetch(`${controllerUrl}/api/v1/vhosts`, {
        method: "POST",
        headers,
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

  let formAllowlists: any[] = [];
  let formBlacklists: any[] = [];

  function addAllowlistRule() {
    formAllowlists = [
      ...formAllowlists,
      { name: "", ips: [], paths: [], bypass_rules: ["*"], enabled: true },
    ];
  }

  function removeAllowlistRule(idx: number) {
    formAllowlists = formAllowlists.filter((_, i) => i !== idx);
  }

  function addBlacklistRule() {
    formBlacklists = [...formBlacklists, { name: "", ips: [], paths: [], enabled: true }];
  }

  function removeBlacklistRule(idx: number) {
    formBlacklists = formBlacklists.filter((_, i) => i !== idx);
  }

  function openCreateForm() {
    editingIndex = null;
    formName = "";
    formHosts = "";
    formBackend = "http://127.0.0.1:8000";
    formSsl = "Auto (Let's Encrypt)";
    formMaxBody = "10MB";
    formRateLimit = "100/m";
    formIsDefault = false;
    formAllowlists = [];
    formBlacklists = [];
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
    formIsDefault = vhost.is_default || false;
    formAllowlists = vhost.allowlists ? JSON.parse(JSON.stringify(vhost.allowlists)) : [];
    formBlacklists = vhost.blacklists ? JSON.parse(JSON.stringify(vhost.blacklists)) : [];
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
        is_default: formIsDefault,
        allowlists: formAllowlists,
        blacklists: formBlacklists,
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
        is_default: formIsDefault,
        rules: ["SQLI-*", "XSS-*", "LFI-*", "RFI-*", "CMDI-*"],
        custom_rules: [],
        blocked_countries: [],
        geoblock_type: "blacklist",
        rate_limit_tiers: [],
        allowlists: formAllowlists,
        blacklists: formBlacklists,
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
      <h1 class="text-2xl font-bold tracking-tight text-white md:text-3xl">Virtual Hosts</h1>
      <p class="text-text-secondary text-sm mt-1">Manage upstream reverse proxies, SSL settings, and custom security policies per domain.</p>
    </div>
    {#if showForm}
      <Button
        on:click={() => (showForm = false)}
        variant="secondary"
        className="flex items-center gap-2 shrink-0"
      >
        <ArrowLeft size={16} />
        <span>Back to List</span>
      </Button>
    {:else}
      <Button
        on:click={openCreateForm}
        variant="primary"
        className="flex items-center gap-2 shrink-0"
      >
        <Plus size={16} />
        <span>Add VHost</span>
      </Button>
    {/if}
  </div>

  {#if showForm}
    <!-- VHost Form Editor -->
    <Card className="max-w-3xl border-border-muted">
      <div class="mb-6 border-b border-border-muted/80 pb-4">
        <h2 class="text-lg font-bold text-white flex items-center gap-2">
          <Globe class="text-accent-blue" size={20} />
          <span>{editingIndex !== null ? "Edit Virtual Host" : "Create New Virtual Host"}</span>
        </h2>
        <p class="text-xs text-text-secondary mt-1">
          Configure upstream server target, hostname constraints, SSL options, and rate thresholds.
        </p>
      </div>

      <div class="space-y-5">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
          <Input
            id="vhost_name"
            label="VHost Name"
            bind:value={formName}
            placeholder="e.g. Main Production API"
            required={true}
          />
          <Input
            id="vhost_domains"
            label="Domains (Comma Separated)"
            bind:value={formHosts}
            placeholder="e.g. api.example.com, example.com"
            required={true}
          />
        </div>

        <div class="space-y-2">
          <label for="vhost_backend" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Backend Proxy Target <span class="text-red-500">*</span>
          </label>
          <div class="flex flex-col md:flex-row gap-3">
            {#if discoveredServices.length > 0}
              <select
                bind:value={formBackend}
                class="bg-slate-950/50 border border-border-muted rounded-xl px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue transition-all font-mono max-w-full md:max-w-xs"
              >
                <option value="" class="bg-bg-secondary">-- Custom Target Address --</option>
                {#each discoveredServices as srv}
                  <option value={srv.value} class="bg-bg-secondary">{srv.label}</option>
                {/each}
              </select>
            {/if}
            <input
              id="vhost_backend"
              type="text"
              bind:value={formBackend}
              placeholder="e.g. http://127.0.0.1:8000"
              class="flex-1 input-field font-mono"
            />
          </div>
        </div>

        <div class="flex items-center gap-2.5 py-1">
          <input
            type="checkbox"
            id="is_default"
            bind:checked={formIsDefault}
            class="w-4 h-4 rounded border-border-muted bg-slate-950 text-accent-blue focus:ring-accent-blue cursor-pointer"
          />
          <label
            for="is_default"
            class="text-sm font-semibold text-text-secondary cursor-pointer select-none"
          >
            Set as Default / Fallback VHost (Responds to unmatched HTTP host headers)
          </label>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
          <div class="space-y-1.5">
            <label for="vhost_ssl" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
              SSL Mode
            </label>
            <select
              id="vhost_ssl"
              bind:value={formSsl}
              class="w-full bg-slate-950/50 border border-border-muted rounded-xl px-3 py-2.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue transition-all"
            >
              <option value="None" class="bg-bg-secondary">None (HTTP only)</option>
              <option value="Auto (Let's Encrypt)" class="bg-bg-secondary">Auto Let's Encrypt (ACME)</option>
              <option value="Local Self-Signed" class="bg-bg-secondary">Local CA Self-Signed</option>
            </select>
          </div>

          <div class="space-y-1.5">
            <label for="vhost_max_body" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Max Request Size
            </label>
            <select
              id="vhost_max_body"
              bind:value={formMaxBody}
              class="w-full bg-slate-950/50 border border-border-muted rounded-xl px-3 py-2.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue transition-all"
            >
              <option value="1MB" class="bg-bg-secondary">1 MB (Aggressive Limit)</option>
              <option value="10MB" class="bg-bg-secondary">10 MB (Default Standard)</option>
              <option value="50MB" class="bg-bg-secondary">50 MB (Media Uploads)</option>
              <option value="100MB" class="bg-bg-secondary">100 MB (Permissive)</option>
            </select>
          </div>

          <div class="space-y-1.5">
            <label for="vhost_ratelimit" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Rate Limit Threshold
            </label>
            <select
              id="vhost_ratelimit"
              bind:value={formRateLimit}
              class="w-full bg-slate-950/50 border border-border-muted rounded-xl px-3 py-2.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue transition-all"
            >
              <option value="60/m" class="bg-bg-secondary">60 requests / min (1 req/sec)</option>
              <option value="100/m" class="bg-bg-secondary">100 requests / min (Default)</option>
              <option value="300/m" class="bg-bg-secondary">300 requests / min (Moderate)</option>
              <option value="600/m" class="bg-bg-secondary">600 requests / min (Permissive)</option>
              <option value="Unlimited" class="bg-bg-secondary">Bypass Rate Limit (Disabled)</option>
            </select>
          </div>
        </div>

        <!-- Allowlists -->
        <div class="space-y-4 border-t border-border-muted pt-6">
          <div class="flex justify-between items-center gap-4">
            <div>
              <h3 class="text-sm font-bold text-white">VHost Allowlists (Bypasses WAF)</h3>
              <p class="text-xs text-text-secondary mt-0.5">
                Explicitly trust clients (by IP or path) to bypass inspection entirely.
              </p>
            </div>
            <Button
              type="button"
              on:click={addAllowlistRule}
              variant="secondary"
              className="text-xs py-1.5 px-3 flex items-center gap-1.5"
            >
              <Plus size={14} /> <span>Add Allowlist Rule</span>
            </Button>
          </div>

          {#if formAllowlists.length === 0}
            <div
              class="text-xs text-text-muted italic border border-border-muted/50 rounded-xl p-4 text-center select-none"
            >
              No VHost-specific allowlists defined.
            </div>
          {:else}
            <div class="space-y-4">
              {#each formAllowlists as rule, idx}
                <div
                  class="bg-slate-950/30 border border-border-muted/80 rounded-xl p-4 space-y-3 relative group"
                >
                  <Button
                    type="button"
                    on:click={() => removeAllowlistRule(idx)}
                    variant="ghost"
                    className="absolute top-3 right-3 text-text-muted hover:text-error p-1 rounded-xl"
                  >
                    <Trash2 size={15} />
                  </Button>

                  <div class="space-y-1.5 pr-8">
                    <Input
                      id={`allow_name_${idx}`}
                      label="Rule Name"
                      bind:value={rule.name}
                      placeholder="e.g. Trust Internal Gateway"
                    />
                  </div>

                  <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="space-y-1.5">
                      <label for={`allow_ips_${idx}`} class="block text-[11px] font-bold text-text-secondary uppercase tracking-wider">
                        IP Addresses (Comma Separated)
                      </label>
                      <input
                        id={`allow_ips_${idx}`}
                        type="text"
                        value={Array.isArray(rule.ips) ? rule.ips.join(", ") : rule.ips}
                        on:input={(e) => handleListInput(e, (arr) => (rule.ips = arr))}
                        placeholder="e.g. 192.168.1.50, 10.0.0.0/8"
                        class="w-full input-field font-mono text-xs"
                      />
                    </div>
                    <div class="space-y-1.5">
                      <label for={`allow_paths_${idx}`} class="block text-[11px] font-bold text-text-secondary uppercase tracking-wider">
                        Paths (Comma Separated)
                      </label>
                      <input
                        id={`allow_paths_${idx}`}
                        type="text"
                        value={Array.isArray(rule.paths) ? rule.paths.join(", ") : rule.paths}
                        on:input={(e) => handleListInput(e, (arr) => (rule.paths = arr))}
                        placeholder="e.g. /assets/*, /webhook"
                        class="w-full input-field font-mono text-xs"
                      />
                    </div>
                  </div>

                  <div class="flex items-center gap-2.5 pt-1">
                    <input
                      type="checkbox"
                      id={`allow_enabled_${idx}`}
                      bind:checked={rule.enabled}
                      class="w-4 h-4 rounded border-border-muted bg-slate-900 text-accent-blue focus:ring-accent-blue cursor-pointer"
                    />
                    <label
                      for={`allow_enabled_${idx}`}
                      class="text-xs font-semibold text-text-secondary cursor-pointer select-none"
                    >
                      Rule Enabled
                    </label>
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </div>

        <!-- Blacklists -->
        <div class="space-y-4 border-t border-border-muted pt-6 pb-6">
          <div class="flex justify-between items-center gap-4">
            <div>
              <h3 class="text-sm font-bold text-white">VHost Blacklists (Blocking)</h3>
              <p class="text-xs text-text-secondary mt-0.5">
                Explicitly block access from specific client IPs or request paths.
              </p>
            </div>
            <Button
              type="button"
              on:click={addBlacklistRule}
              variant="secondary"
              className="text-xs py-1.5 px-3 flex items-center gap-1.5"
            >
              <Plus size={14} /> <span>Add Blacklist Rule</span>
            </Button>
          </div>

          {#if formBlacklists.length === 0}
            <div
              class="text-xs text-text-muted italic border border-border-muted/50 rounded-xl p-4 text-center select-none"
            >
              No VHost-specific blacklists defined.
            </div>
          {:else}
            <div class="space-y-4">
              {#each formBlacklists as rule, idx}
                <div
                  class="bg-slate-950/30 border border-border-muted/80 rounded-xl p-4 space-y-3 relative group"
                >
                  <Button
                    type="button"
                    on:click={() => removeBlacklistRule(idx)}
                    variant="ghost"
                    className="absolute top-3 right-3 text-text-muted hover:text-error p-1 rounded-xl"
                  >
                    <Trash2 size={15} />
                  </Button>

                  <div class="space-y-1.5 pr-8">
                    <Input
                      id={`black_name_${idx}`}
                      label="Rule Name"
                      bind:value={rule.name}
                      placeholder="e.g. Block Abusive Crawler"
                    />
                  </div>

                  <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="space-y-1.5">
                      <label for={`black_ips_${idx}`} class="block text-[11px] font-bold text-text-secondary uppercase tracking-wider">
                        IP Addresses (Comma Separated)
                      </label>
                      <input
                        id={`black_ips_${idx}`}
                        type="text"
                        value={Array.isArray(rule.ips) ? rule.ips.join(", ") : rule.ips}
                        on:input={(e) => handleListInput(e, (arr) => (rule.ips = arr))}
                        placeholder="e.g. 192.168.1.100, 10.0.0.0/24"
                        class="w-full input-field font-mono text-xs"
                      />
                    </div>
                    <div class="space-y-1.5">
                      <label for={`black_paths_${idx}`} class="block text-[11px] font-bold text-text-secondary uppercase tracking-wider">
                        Paths (Comma Separated)
                      </label>
                      <input
                        id={`black_paths_${idx}`}
                        type="text"
                        value={Array.isArray(rule.paths) ? rule.paths.join(", ") : rule.paths}
                        on:input={(e) => handleListInput(e, (arr) => (rule.paths = arr))}
                        placeholder="e.g. /admin/config/*, /config.php"
                        class="w-full input-field font-mono text-xs"
                      />
                    </div>
                  </div>

                  <div class="flex items-center gap-2.5 pt-1">
                    <input
                      type="checkbox"
                      id={`black_enabled_${idx}`}
                      bind:checked={rule.enabled}
                      class="w-4 h-4 rounded border-border-muted bg-slate-905 text-accent-blue focus:ring-accent-blue cursor-pointer"
                    />
                    <label
                      for={`black_enabled_${idx}`}
                      class="text-xs font-semibold text-text-secondary cursor-pointer select-none"
                    >
                      Rule Enabled
                    </label>
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </div>

        <div class="pt-6 border-t border-border-muted flex justify-end gap-3">
          <Button
            on:click={() => (showForm = false)}
            variant="ghost"
          >
            Cancel
          </Button>
          <Button
            on:click={handleSaveForm}
            variant="primary"
            className="flex items-center gap-2"
          >
            <Save size={16} />
            <span>Save Configuration</span>
          </Button>
        </div>
      </div>
    </Card>
  {:else}
    <!-- VHost List Table -->
    <Card className="p-0 overflow-hidden">
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
          <tr class="hover:bg-slate-900/20 border-b border-border-muted/40 last:border-0 transition-colors group">
            <td class="px-6 py-4 whitespace-nowrap">
              <div class="flex items-center gap-3">
                <div
                  class="p-2.5 bg-slate-950/60 rounded-xl text-text-muted group-hover:text-accent-blue transition-colors border border-border-muted shadow-inner"
                >
                  <Globe size={16} />
                </div>
                <div class="flex flex-col">
                  <div class="flex items-center gap-2">
                    <span class="text-text-primary font-bold">{host.name}</span>
                    {#if host.is_default}
                      <span
                        class="text-[9px] font-extrabold px-1.5 py-0.5 rounded bg-accent-blue/20 text-accent-blue border border-accent-blue/15 tracking-wider uppercase"
                        >FALLBACK</span
                      >
                    {/if}
                  </div>
                  <span class="text-text-muted text-xs mt-0.5 font-medium"
                    >{host.hosts.length > 0 ? host.hosts.join(", ") : "*"}</span
                  >
                </div>
              </div>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-text-secondary font-mono text-xs">
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
            <td class="px-6 py-4 whitespace-nowrap text-text-secondary text-sm">
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
                class="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity"
              >
                <Button
                  variant="ghost"
                  on:click={() => openEditForm(i)}
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
            <td colspan="6" class="px-6 py-12 text-center text-text-muted italic select-none"
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
