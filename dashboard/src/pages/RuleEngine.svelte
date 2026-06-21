<script lang="ts">
  import { onMount } from "svelte";
  import {
    Shield,
    Database,
    Code,
    FolderOpen,
    Terminal,
    ArrowRightLeft,
    Bot,
    Globe,
    Plus,
    Trash2,
    Edit2,
    Play,
    CheckCircle,
    AlertTriangle,
  } from "lucide-svelte";
  import { vhostsList } from '../lib/stores';
  import { toast } from '../lib/toast';
  import Card from '../components/ui/Card.svelte';
  import Badge from '../components/ui/Badge.svelte';
  import DataTable from '../components/ui/DataTable.svelte';
  import ConfirmationModal from '../components/ui/ConfirmationModal.svelte';
  import PresetDetailsModal from '../components/ui/PresetDetailsModal.svelte';

  const controllerUrl = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8080';

  let selectedVhostIndex = 0;

  // Custom Rules editor state
  let ruleName = "";
  let conditionFieldType = "path";
  let customHeaderName = "User-Agent";
  let operator = "contains";
  let conditionValue = "";
  let action = "block";
  let redirectUrl = "";
  let editingRuleId: string | null = null;
  let showForm = false; // toggle for responsive form

  // Modal State
  let showDeleteModal = false;
  let ruleToDelete: string | null = null;
  let showPresetModal = false;
  let selectedPreset: any = null;

  // Sandbox simulation state
  let testPayload = "";
  let simulationResult: {
    status: "idle" | "testing" | "triggered" | "passed";
    ruleName?: string;
  } = { status: "idle" };

  // Presets
  const presetGroups = [
    {
      key: "sqli",
      name: "SQL Injection Protection",
      rule_pattern: "SQLI-*",
      icon: Database,
      severity: "CRITICAL",
      rules: [
        { id: "SQLI-001", name: "SQL Injection (Basic)" },
        { id: "SQLI-002", name: "SQL Injection (Blind/Time)" },
        { id: "SQLI-003", name: "SQL Injection (Union)" },
      ],
    },
    {
      key: "xss",
      name: "Cross-Site Scripting (XSS)",
      rule_pattern: "XSS-*",
      icon: Code,
      severity: "HIGH",
      rules: [
        { id: "XSS-001", name: "XSS - Script Tag" },
        { id: "XSS-002", name: "XSS - Event Handler" },
      ],
    },
    {
      key: "lfi",
      name: "File Inclusion Protection",
      rule_pattern: "LFI-*",
      icon: FolderOpen,
      severity: "HIGH",
      rules: [
        { id: "LFI-001", name: "Local File Inclusion" },
        { id: "RFI-001", name: "Remote File Inclusion" },
      ],
    },
    {
      key: "cmdi",
      name: "OS Command Injection",
      rule_pattern: "CMDI-*",
      icon: Terminal,
      severity: "HIGH",
      rules: [{ id: "CMDI-001", name: "Command Exec Pattern" }],
    },
    {
      key: "ssrf",
      name: "Request Forgery Protection",
      rule_pattern: "SSRF-*",
      icon: ArrowRightLeft,
      severity: "MEDIUM",
      rules: [{ id: "SSRF-001", name: "SSRF localhost bypass" }],
    },
    {
      key: "bot",
      name: "Bots & Scanners Filter",
      rule_pattern: "BOT-*",
      icon: Bot,
      severity: "MEDIUM",
      rules: [{ id: "BOT-001", name: "Bad User-Agent" }],
    },
  ];

  async function saveVhosts(silent = false) {
    try {
      await fetch(`${controllerUrl}/api/v1/vhosts`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify($vhostsList),
      });
      if (!silent) toast.success("Configuration saved successfully!");
    } catch (e) {
      console.error("Failed to save rules:", e);
      toast.error("Failed to save configuration. Please check backend connection.");
    }
  }

  async function toggleModule(pattern: string, checked: boolean) {
    if ($vhostsList.length === 0) return;
    const host = $vhostsList[selectedVhostIndex];
    let activeRules = [...(host.rules || [])];

    if (checked) {
      if (!activeRules.includes(pattern)) activeRules.push(pattern);
      if (pattern === "LFI-*" && !activeRules.includes("RFI-*"))
        activeRules.push("RFI-*");
      toast.info(`Module enabled: ${pattern}`);
    } else {
      activeRules = activeRules.filter((r) => r !== pattern);
      if (pattern === "LFI-*")
        activeRules = activeRules.filter((r) => r !== "RFI-*");
      toast.warning(`Module disabled: ${pattern}`);
    }

    $vhostsList[selectedVhostIndex].rules = activeRules;
    vhostsList.set($vhostsList); // trigger reactivity
    await saveVhosts(true);
  }

  function openPresetDetails(group: any) {
    selectedPreset = group;
    showPresetModal = true;
  }

  async function handleToggleGranularRule(event: CustomEvent<{ ruleId: string; enabled: boolean }>) {
    if (!selectedPreset) return;
    const { ruleId, enabled } = event.detail;
    const host = $vhostsList[selectedVhostIndex];
    let activeRules = [...(host.rules || [])];

    // If wildcard is active and we are disabling a single rule
    if (activeRules.includes(selectedPreset.rule_pattern)) {
      if (!enabled) {
        activeRules = activeRules.filter(r => r !== selectedPreset.rule_pattern);
        selectedPreset.rules.forEach((r: any) => {
          if (r.id !== ruleId && !activeRules.includes(r.id)) {
            activeRules.push(r.id);
          }
        });
        toast.info(`Converted ${selectedPreset.rule_pattern} to granular rules. Disabled ${ruleId}.`);
      }
    } else {
      if (enabled) {
        if (!activeRules.includes(ruleId)) activeRules.push(ruleId);
        toast.success(`Enabled signature ${ruleId}`);
      } else {
        activeRules = activeRules.filter(r => r !== ruleId);
        toast.warning(`Disabled signature ${ruleId}`);
      }
      
      const allEnabled = selectedPreset.rules.every((r: any) => activeRules.includes(r.id));
      if (allEnabled) {
        selectedPreset.rules.forEach((r: any) => {
          activeRules = activeRules.filter((ar) => ar !== r.id);
        });
        activeRules.push(selectedPreset.rule_pattern);
        toast.info(`All signatures enabled. Reverting to wildcard ${selectedPreset.rule_pattern}.`);
      }
    }

    $vhostsList[selectedVhostIndex].rules = activeRules;
    vhostsList.set($vhostsList);
    await saveVhosts(true);
  }

  function displayCondition(rule: any): string {
    let field = rule.condition_type;
    if (field.startsWith("header:"))
      field = `Header [${field.substring(7).toUpperCase()}]`;
    else field = field.toUpperCase();
    let op =
      rule.operator === "equals"
        ? "="
        : rule.operator === "starts_with"
          ? "starts with"
          : "contains";
    return `${field} ${op} "${rule.condition_value}"`;
  }

  async function toggleCustomRule(ruleId: string) {
    if ($vhostsList.length === 0) return;
    let enabledNow = false;
    $vhostsList[selectedVhostIndex].custom_rules = $vhostsList[
      selectedVhostIndex
    ].custom_rules.map((r) => {
      if (r.id === ruleId) {
        enabledNow = !r.enabled;
        return { ...r, enabled: enabledNow };
      }
      return r;
    });
    vhostsList.set($vhostsList);
    toast.info(`Custom rule ${enabledNow ? 'enabled' : 'disabled'}.`);
    await saveVhosts(true);
  }

  function confirmDeleteRule(ruleId: string) {
    ruleToDelete = ruleId;
    showDeleteModal = true;
  }

  async function executeDeleteRule() {
    if (!ruleToDelete) return;
    $vhostsList[selectedVhostIndex].custom_rules = $vhostsList[
      selectedVhostIndex
    ].custom_rules.filter((r) => r.id !== ruleToDelete);
    vhostsList.set($vhostsList);
    toast.success("Custom rule deleted successfully.");
    await saveVhosts(true);
    showDeleteModal = false;
    ruleToDelete = null;
  }

  function editRule(rule: any) {
    editingRuleId = rule.id;
    ruleName = rule.name;
    if (rule.condition_type.startsWith("header:")) {
      conditionFieldType = "header";
      customHeaderName = rule.condition_type.replace("header:", "");
    } else {
      conditionFieldType = rule.condition_type;
    }
    operator = rule.operator;
    conditionValue = rule.condition_value;
    action = rule.action;
    redirectUrl = rule.action_value;
    showForm = true;
  }

  function cancelEdit() {
    editingRuleId = null;
    ruleName = "";
    conditionFieldType = "path";
    customHeaderName = "User-Agent";
    operator = "contains";
    conditionValue = "";
    action = "block";
    redirectUrl = "";
    showForm = false;
  }

  function handleSaveCustomRule() {
    if ($vhostsList.length === 0 || !ruleName || !conditionValue) {
      toast.warning("Please fill in all required fields.");
      return;
    }
    if (action === "redirect" && !redirectUrl) {
      toast.warning("Redirect URL is required for redirect action.");
      return;
    }

    let finalConditionType =
      conditionFieldType === "header"
        ? `header:${customHeaderName.trim().toLowerCase()}`
        : conditionFieldType;
    const currentVhost = $vhostsList[selectedVhostIndex];
    if (!currentVhost.custom_rules) currentVhost.custom_rules = [];

    const newRuleData = {
      name: ruleName,
      condition_type: finalConditionType,
      operator: operator,
      condition_value: conditionValue,
      action: action,
      action_value: action === "redirect" ? redirectUrl : "",
    };

    if (editingRuleId) {
      currentVhost.custom_rules = currentVhost.custom_rules.map((r) =>
        r.id === editingRuleId ? { ...r, ...newRuleData } : r,
      );
      toast.success("Custom rule updated successfully!");
    } else {
      currentVhost.custom_rules.push({
        id: "CR-" + Math.floor(100 + Math.random() * 900),
        ...newRuleData,
        enabled: true,
      });
      toast.success("New custom rule created!");
    }

    vhostsList.set($vhostsList);
    saveVhosts(true);
    cancelEdit();
  }

  function runSimulation() {
    if (!testPayload) return;
    simulationResult = { status: "testing" };
    setTimeout(() => {
      const payloadLower = testPayload.toLowerCase();
      const host = $vhostsList[selectedVhostIndex];
      const activeRules = host ? host.rules || [] : [];

      if (
        activeRules.includes("SQLI-*") &&
        (payloadLower.includes("union select") ||
          payloadLower.includes("or 1=1"))
      ) {
        simulationResult = { status: "triggered", ruleName: "SQLI-*" };
        return;
      }
      if (
        activeRules.includes("XSS-*") &&
        (payloadLower.includes("<script") || payloadLower.includes("onload="))
      ) {
        simulationResult = { status: "triggered", ruleName: "XSS-*" };
        return;
      }
      if (
        activeRules.includes("LFI-*") &&
        (payloadLower.includes("../") || payloadLower.includes("etc/passwd"))
      ) {
        simulationResult = { status: "triggered", ruleName: "LFI-*" };
        return;
      }
      if (
        activeRules.includes("CMDI-*") &&
        (payloadLower.includes("; rm ") || payloadLower.includes("&& "))
      ) {
        simulationResult = { status: "triggered", ruleName: "CMDI-*" };
        return;
      }

      const activeCustomRules = host
        ? (host.custom_rules || []).filter((r) => r.enabled)
        : [];
      for (const rule of activeCustomRules) {
        let isMatch = false;
        const matchVal = rule.condition_value.toLowerCase();
        if (rule.operator === "equals") isMatch = payloadLower === matchVal;
        else if (rule.operator === "starts_with")
          isMatch = payloadLower.startsWith(matchVal);
        else isMatch = payloadLower.includes(matchVal);

        if (isMatch) {
          simulationResult = {
            status: "triggered",
            ruleName: `[${rule.name}]`,
          };
          return;
        }
      }
      simulationResult = { status: "passed" };
    }, 600);
  }
</script>

<div class="space-y-6">
  <!-- Header -->
  <div>
    <h1 class="text-2xl font-bold text-slate-100 tracking-tight">
      WAF Rules Engine
    </h1>
    <p class="text-slate-400 mt-1">
      Configure preset protection modules and user-defined custom logic rules.
    </p>
  </div>

  <!-- Domain Selector -->
  <Card className="flex items-center gap-4 py-4">
    <Globe class="text-blue-500" size={20} />
    <span class="text-sm font-bold text-slate-400 uppercase tracking-wider"
      >Select virtual host:</span
    >
    {#if $vhostsList.length > 0}
      <select
        bind:value={selectedVhostIndex}
        class="bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-sm outline-none focus:border-blue-500 text-blue-400 font-bold cursor-pointer min-w-[250px]"
      >
        {#each $vhostsList as host, index}
          <option value={index}>{host.hosts[0] || host.name}</option>
        {/each}
      </select>
    {:else}
      <span class="text-sm font-mono text-red-500"
        >No virtual hosts available</span
      >
    {/if}
  </Card>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Main Left Panel (Spans 2 columns on Desktop) -->
    <div class="lg:col-span-2 space-y-6">
      <!-- Preset Modules -->
      <div>
        <h2 class="text-lg font-semibold text-slate-200 mb-4">
          Preset Modules
        </h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          {#each presetGroups as group}
            {@const hostRules = $vhostsList[selectedVhostIndex]
              ? $vhostsList[selectedVhostIndex].rules || []
              : []}
            {@const isEnabled = hostRules.includes(group.rule_pattern)}
            <Card className="p-4 flex flex-col gap-3">
              <div class="flex items-start justify-between">
                <div class="flex items-center gap-3">
                  <div class="p-2 bg-slate-900 rounded-lg text-slate-400">
                    <svelte:component this={group.icon} size={18} />
                  </div>
                  <div>
                    <h4 class="font-bold text-sm text-slate-200">{group.name}</h4>
                    <div class="flex items-center gap-2 mt-0.5">
                      <p class="text-xs text-slate-500">{group.rules.length} signatures</p>
                      <button on:click={() => openPresetDetails(group)} class="text-xs text-blue-400 hover:text-blue-300 font-medium hover:underline transition-colors">Details</button>
                    </div>
                  </div>
                </div>
                <label class="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={isEnabled}
                    on:change={(e) =>
                      toggleModule(group.rule_pattern, e.currentTarget.checked)}
                    class="sr-only peer"
                  />
                  <div
                    class="w-11 h-6 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"
                  ></div>
                </label>
              </div>
            </Card>
          {/each}
        </div>
      </div>

      <!-- Custom Rules Table -->
      <div>
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-lg font-semibold text-slate-200">Custom Rules</h2>
          <button
            on:click={() => (showForm = !showForm)}
            class="bg-slate-800 hover:bg-slate-700 text-blue-400 text-sm font-medium px-4 py-2 rounded-lg transition-colors border border-slate-700 flex items-center gap-2"
          >
            {#if showForm}
              Cancel
            {:else}
              <Plus size={16} /> Build Rule
            {/if}
          </button>
        </div>
        <Card className="p-0 overflow-hidden">
          <DataTable
            columns={[
              "ID",
              "Rule Name",
              "Condition",
              "Action",
              "Active",
              "Options",
            ]}
          >
            {#if $vhostsList[selectedVhostIndex]?.custom_rules?.length > 0}
              {#each $vhostsList[selectedVhostIndex].custom_rules as rule}
                <tr
                  class="hover:bg-slate-700/30 transition-colors {rule.enabled
                    ? ''
                    : 'opacity-50'}"
                >
                  <td
                    class="px-6 py-4 whitespace-nowrap text-blue-400 font-mono text-xs"
                    >{rule.id}</td
                  >
                  <td
                    class="px-6 py-4 whitespace-nowrap text-slate-200 font-medium"
                    >{rule.name}</td
                  >
                  <td
                    class="px-6 py-4 whitespace-nowrap text-slate-400 font-mono text-xs"
                    >{displayCondition(rule)}</td
                  >
                  <td class="px-6 py-4 whitespace-nowrap">
                    <Badge
                      variant={rule.action === "redirect"
                        ? "primary"
                        : "danger"}
                    >
                      {rule.action.toUpperCase()}
                    </Badge>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-center">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      on:change={() => toggleCustomRule(rule.id)}
                      class="rounded border-slate-600 bg-slate-800 text-blue-500 cursor-pointer"
                    />
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-right">
                    <div class="flex justify-end gap-3">
                      <button
                        on:click={() => editRule(rule)}
                        class="text-slate-400 hover:text-blue-400 transition-colors"
                        ><Edit2 size={16} /></button
                      >
                      <button on:click={() => confirmDeleteRule(rule.id)} class="text-slate-400 hover:text-red-400 transition-colors"><Trash2 size={16} /></button>
                    </div>
                  </td>
                </tr>
              {/each}
            {:else}
              <tr>
                <td
                  colspan="6"
                  class="px-6 py-8 text-center text-slate-500 italic"
                  >No custom rules defined. Click "Build Rule" to add one.</td
                >
              </tr>
            {/if}
          </DataTable>
        </Card>
      </div>
    </div>

    <!-- Right Panel: Rule Builder Form & Sandbox -->
    <div class="space-y-6">
      {#if showForm}
        <Card
          className="flex flex-col gap-4 border-blue-500/30 shadow-lg shadow-blue-500/10 transition-all"
        >
          <div
            class="flex items-center justify-between border-b border-slate-800 pb-3"
          >
            <h3 class="font-bold text-slate-200 flex items-center gap-2">
              <Terminal size={18} class="text-blue-400" />
              {editingRuleId ? "Edit Rule" : "New Custom Rule"}
            </h3>
            {#if editingRuleId}
              <Badge variant="primary">{editingRuleId}</Badge>
            {/if}
          </div>

          <div class="space-y-4">
            <div class="flex flex-col gap-1.5">
              <label
                class="text-xs uppercase tracking-wider text-slate-500 font-bold"
                >Rule Name</label
              >
              <input
                type="text"
                placeholder="e.g. Block login scanner"
                bind:value={ruleName}
                class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:border-blue-500 outline-none transition-colors"
              />
            </div>

            <div class="grid grid-cols-2 gap-3">
              <div class="flex flex-col gap-1.5">
                <label
                  class="text-xs uppercase tracking-wider text-slate-500 font-bold"
                  >Target Field</label
                >
                <select
                  bind:value={conditionFieldType}
                  class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:border-blue-500 outline-none"
                >
                  <option value="path">URL Path</option>
                  <option value="query">Query Param</option>
                  <option value="body">Request Body</option>
                  <option value="header">HTTP Header</option>
                </select>
              </div>
              <div class="flex flex-col gap-1.5">
                <label
                  class="text-xs uppercase tracking-wider text-slate-500 font-bold"
                  >Operator</label
                >
                <select
                  bind:value={operator}
                  class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:border-blue-500 outline-none"
                >
                  <option value="contains">Contains</option>
                  <option value="equals">Equals exactly</option>
                  <option value="starts_with">Starts with</option>
                </select>
              </div>
            </div>

            {#if conditionFieldType === "header"}
              <div class="flex flex-col gap-1.5">
                <label
                  class="text-xs uppercase tracking-wider text-slate-500 font-bold"
                  >Header Name</label
                >
                <input
                  type="text"
                  placeholder="e.g. User-Agent"
                  bind:value={customHeaderName}
                  class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono focus:border-blue-500 outline-none"
                />
              </div>
            {/if}

            <div class="flex flex-col gap-1.5">
              <label
                class="text-xs uppercase tracking-wider text-slate-500 font-bold"
                >Match Value</label
              >
              <input
                type="text"
                placeholder="e.g. /wp-admin"
                bind:value={conditionValue}
                class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono focus:border-blue-500 outline-none"
              />
            </div>

            <div
              class="flex flex-col gap-1.5 border-t border-slate-800 pt-4 mt-2"
            >
              <label
                class="text-xs uppercase tracking-wider text-slate-500 font-bold"
                >Action</label
              >
              <select
                bind:value={action}
                class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:border-blue-500 outline-none font-bold"
              >
                <option value="block">Block (403)</option>
                <option value="redirect">Redirect (302)</option>
              </select>
            </div>

            {#if action === "redirect"}
              <div class="flex flex-col gap-1.5">
                <label
                  class="text-xs uppercase tracking-wider text-slate-500 font-bold"
                  >Redirect URL</label
                >
                <input
                  type="text"
                  placeholder="http://..."
                  bind:value={redirectUrl}
                  class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono focus:border-blue-500 outline-none"
                />
              </div>
            {/if}
          </div>

          <div class="flex gap-3 pt-2">
            <button
              on:click={cancelEdit}
              class="flex-1 bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium py-2 rounded-lg transition-colors"
              >Cancel</button
            >
            <button
              on:click={handleSaveCustomRule}
              class="flex-1 bg-blue-600 hover:bg-blue-500 text-white font-medium py-2 rounded-lg transition-colors shadow-lg shadow-blue-500/20"
              >Save Rule</button
            >
          </div>
        </Card>
      {/if}

      <!-- Sandbox -->
      <Card className="flex flex-col gap-4">
        <div
          class="flex items-center justify-between border-b border-slate-800 pb-3"
        >
          <h3 class="font-bold text-slate-200 flex items-center gap-2">
            <Play size={18} class="text-emerald-400" /> Sandbox Simulator
          </h3>
        </div>
        <p class="text-xs text-slate-500">
          Test payloads against active modules and custom rules instantly.
        </p>

        <div class="relative">
          <textarea
            bind:value={testPayload}
            class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm font-mono text-slate-300 focus:border-emerald-500 outline-none h-24 resize-none transition-colors"
            placeholder="Paste malicious payload here..."
          ></textarea>
          <button
            on:click={runSimulation}
            class="absolute bottom-3 right-3 bg-slate-800 hover:bg-slate-700 text-emerald-400 p-2 rounded-lg transition-colors border border-slate-700"
            ><Play size={16} /></button
          >
        </div>

        {#if simulationResult.status === "testing"}
          <div
            class="p-3 bg-slate-800 rounded-lg text-center text-slate-400 text-xs flex justify-center items-center gap-2 animate-pulse"
          >
            <div
              class="w-4 h-4 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin"
            ></div>
             Simulating...
          </div>
        {:else if simulationResult.status === "triggered"}
          <div
            class="p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center justify-between"
          >
            <div class="flex items-center gap-2 text-red-400 font-bold text-xs">
              <AlertTriangle size={16} /> BLOCKED
            </div>
            <span
              class="text-slate-400 text-xs font-mono truncate max-w-[150px]"
              title={simulationResult.ruleName}
              >{simulationResult.ruleName}</span
            >
          </div>
        {:else if simulationResult.status === "passed"}
          <div
            class="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg flex items-center gap-2 text-emerald-400 font-bold text-xs"
          >
            <CheckCircle size={16} /> ALLOWED (No triggers)
          </div>
        {/if}
      </Card>
    </div>
  </div>
</div>

<ConfirmationModal
  show={showDeleteModal}
  title="Delete Custom Rule"
  message="Are you sure you want to permanently delete this rule? Traffic currently matched by this rule will no longer be blocked/redirected."
  confirmText="Delete Rule"
  on:confirm={executeDeleteRule}
  on:cancel={() => { showDeleteModal = false; ruleToDelete = null; }}
/>

<PresetDetailsModal
  show={showPresetModal}
  preset={selectedPreset}
  activeRules={$vhostsList[selectedVhostIndex]?.rules || []}
  on:close={() => showPresetModal = false}
  on:toggleRule={handleToggleGranularRule}
/>
