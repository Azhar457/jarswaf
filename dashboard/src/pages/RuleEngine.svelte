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
  import { vhostsList, customRulesList, token } from "../lib/stores";
  import { toast } from "../lib/toast";
  import Card from "../components/ui/Card.svelte";
  import Badge from "../components/ui/Badge.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import ConfirmationModal from "../components/ui/ConfirmationModal.svelte";
  import PresetDetailsModal from "../components/ui/PresetDetailsModal.svelte";
  import Button from "../components/ui/Button.svelte";
  import Input from "../components/ui/Input.svelte";

  const controllerUrl =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:8080";

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
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if ($token) {
        headers["Authorization"] = `Bearer ${$token}`;
      }
      await fetch(`${controllerUrl}/api/v1/vhosts`, {
        method: "POST",
        headers,
        body: JSON.stringify($vhostsList),
      });
      if (!silent) toast.success("Configuration saved successfully!");
    } catch (e) {
      console.error("Failed to save WAF configuration:", e);
      toast.error("Failed to save configuration. Please check backend connection.");
    }
  }

  async function toggleModule(pattern: string, checked: boolean) {
    if ($vhostsList.length === 0) return;
    const host = $vhostsList[selectedVhostIndex];
    let activeRules = [...(host.rules || [])];

    if (checked) {
      if (!activeRules.includes(pattern)) activeRules.push(pattern);
      if (pattern === "LFI-*" && !activeRules.includes("RFI-*")) activeRules.push("RFI-*");
      toast.info(`Module enabled: ${pattern}`);
    } else {
      activeRules = activeRules.filter((r) => r !== pattern);
      if (pattern === "LFI-*") activeRules = activeRules.filter((r) => r !== "RFI-*");
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

  async function handleToggleGranularRule(
    event: CustomEvent<{ ruleId: string; enabled: boolean }>,
  ) {
    if (!selectedPreset) return;
    const { ruleId, enabled } = event.detail;
    const host = $vhostsList[selectedVhostIndex];
    let activeRules = [...(host.rules || [])];

    // If wildcard is active and we are disabling a single rule
    if (activeRules.includes(selectedPreset.rule_pattern)) {
      if (!enabled) {
        activeRules = activeRules.filter((r) => r !== selectedPreset.rule_pattern);
        selectedPreset.rules.forEach((r: any) => {
          if (r.id !== ruleId && !activeRules.includes(r.id)) {
            activeRules.push(r.id);
          }
        });
        toast.info(
          `Converted ${selectedPreset.rule_pattern} to granular rules. Disabled ${ruleId}.`,
        );
      }
    } else {
      if (enabled) {
        if (!activeRules.includes(ruleId)) activeRules.push(ruleId);
        toast.success(`Enabled signature ${ruleId}`);
      } else {
        activeRules = activeRules.filter((r) => r !== ruleId);
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
    if (field.startsWith("header:")) field = `Header [${field.substring(7).toUpperCase()}]`;
    else field = field.toUpperCase();
    let op =
      rule.operator === "equals"
        ? "="
        : rule.operator === "starts_with"
          ? "starts with"
          : "contains";
    return `${field} ${op} "${rule.condition_value}"`;
  }

  async function saveCustomRules() {
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if ($token) {
        headers["Authorization"] = `Bearer ${$token}`;
      }
      const response = await fetch(`${controllerUrl}/api/v1/custom-rules`, {
        method: "POST",
        headers,
        body: JSON.stringify($customRulesList),
      });
      if (!response.ok) throw new Error("Failed to save rules");
    } catch (e) {
      console.error(e);
      toast.error("Failed to save custom rules to backend.");
    }
  }

  function isRuleBound(ruleId: string): boolean {
    if ($vhostsList.length === 0) return false;
    const vhost = $vhostsList[selectedVhostIndex];
    return vhost.custom_rules ? vhost.custom_rules.includes(ruleId) : false;
  }

  async function toggleCustomRule(ruleId: string) {
    if ($vhostsList.length === 0) return;
    const vhost = $vhostsList[selectedVhostIndex];
    if (!vhost.custom_rules) vhost.custom_rules = [];

    if (vhost.custom_rules.includes(ruleId)) {
      vhost.custom_rules = vhost.custom_rules.filter((id) => id !== ruleId);
      toast.info("Rule unbound from Virtual Host.");
    } else {
      vhost.custom_rules = [...vhost.custom_rules, ruleId];
      toast.info("Rule bound to Virtual Host.");
    }
    vhostsList.set($vhostsList);
    await saveVhosts(true);
  }

  async function toggleRuleGlobalEnabled(ruleId: string) {
    $customRulesList = $customRulesList.map((r) =>
      r.id === ruleId ? { ...r, enabled: !r.enabled } : r,
    );
    toast.info("Global rule state updated.");
    await saveCustomRules();
  }

  function confirmDeleteRule(ruleId: string) {
    ruleToDelete = ruleId;
    showDeleteModal = true;
  }

  async function executeDeleteRule() {
    if (!ruleToDelete) return;
    $customRulesList = $customRulesList.filter((r) => r.id !== ruleToDelete);

    // Also clean up references from vhosts
    $vhostsList = $vhostsList.map((v) => {
      if (v.custom_rules) {
        v.custom_rules = v.custom_rules.filter((id) => id !== ruleToDelete);
      }
      return v;
    });

    vhostsList.set($vhostsList);
    toast.success("Custom rule deleted globally.");
    await saveCustomRules();
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

  async function handleSaveCustomRule() {
    if (!ruleName || !conditionValue) {
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

    const newRuleData = {
      name: ruleName,
      condition_type: finalConditionType,
      operator: operator,
      condition_value: conditionValue,
      action: action,
      action_value: action === "redirect" ? redirectUrl : "",
    };

    if (editingRuleId) {
      $customRulesList = $customRulesList.map((r) =>
        r.id === editingRuleId ? { ...r, ...newRuleData } : r,
      );
      toast.success("Custom rule updated successfully!");
    } else {
      const newId = "CR-" + Math.floor(100 + Math.random() * 900);
      $customRulesList = [
        ...$customRulesList,
        {
          id: newId,
          ...newRuleData,
          enabled: true,
        },
      ];
      toast.success("New custom rule created globally!");
    }

    await saveCustomRules();
    cancelEdit();
  }

  function runSimulation() {
    if (!testPayload) {
      toast.warning("Please enter a test payload.");
      return;
    }

    simulationResult = { status: "testing" };

    setTimeout(() => {
      // Basic signature-based client-side simulator
      const payloadLower = testPayload.toLowerCase();
      let triggeredRule = "";

      // SQLI
      if (
        payloadLower.includes("select") ||
        payloadLower.includes("union") ||
        payloadLower.includes("insert") ||
        payloadLower.includes("' or") ||
        payloadLower.includes("1=1")
      ) {
        triggeredRule = "SQLI-001 (SQL Injection Pattern Detected)";
      }
      // XSS
      else if (
        payloadLower.includes("<script") ||
        payloadLower.includes("onerror") ||
        payloadLower.includes("onload=") ||
        payloadLower.includes("javascript:")
      ) {
        triggeredRule = "XSS-001 (Cross-Site Scripting Pattern Detected)";
      }
      // CMDI
      else if (
        payloadLower.includes("curl ") ||
        payloadLower.includes("wget ") ||
        payloadLower.includes("sh ") ||
        payloadLower.includes("bash ") ||
        payloadLower.includes("whoami")
      ) {
        triggeredRule = "CMDI-001 (OS Command Execution Pattern Detected)";
      }
      // Custom Rules
      else {
        for (const rule of $customRulesList) {
          if (!rule.enabled || !isRuleBound(rule.id)) continue;
          if (rule.condition_type === "body" && testPayload.includes(rule.condition_value)) {
            triggeredRule = `${rule.id} (${rule.name})`;
            break;
          }
        }
      }

      if (triggeredRule) {
        simulationResult = { status: "triggered", ruleName: triggeredRule };
        toast.error(`WAF Triggered: Request blocked by ${triggeredRule}`);
      } else {
        simulationResult = { status: "passed" };
        toast.success("Request passed successfully.");
      }
    }, 800);
  }
</script>

<div class="space-y-6 max-h-full overflow-y-auto pr-1">
  <!-- Header -->
  <div class="flex justify-between items-center gap-4">
    <div>
      <h1 class="text-2xl font-bold tracking-tight text-white md:text-3xl">Security Engine</h1>
      <p class="text-text-secondary text-sm mt-1">
        Configure WAF Core Rule Sets (CRS) and custom detection rules per Virtual Host.
      </p>
    </div>

    <!-- Active VHost Selector -->
    <div class="flex items-center gap-3 shrink-0">
      <span class="text-xs font-bold text-text-secondary uppercase tracking-wider hidden sm:inline">Active Host</span>
      <select
        bind:value={selectedVhostIndex}
        class="bg-slate-950/50 border border-border-muted rounded-xl px-4 py-2.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue transition-all"
      >
        {#each $vhostsList as vhost, idx}
          <option value={idx} class="bg-bg-secondary">{vhost.name} ({vhost.hosts[0] || "*"})</option>
        {/each}
      </select>
    </div>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
    <!-- Left Column: Core Rule Set & Custom Rules List -->
    <div class="lg:col-span-2 space-y-6">
      <!-- WAF Modules Grid -->
      <div class="space-y-4">
        <h2 class="text-lg font-bold text-white flex items-center gap-2">
          <Shield size={18} class="text-accent-blue" />
          <span>Core Rule Sets (CRS)</span>
        </h2>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          {#each presetGroups as group}
            {@const isEnabled = $vhostsList[selectedVhostIndex]?.rules?.includes(group.rule_pattern) || false}
            <Card
              className="flex items-center p-5 border-border-muted transition-all duration-200"
              interactive={true}
            >
              <div
                class="p-3 bg-slate-950/60 border border-border-muted/80 rounded-2xl text-text-muted hover:text-accent-blue transition-colors shadow-inner mr-4 shrink-0"
              >
                <svelte:component this={group.icon} size={20} />
              </div>
              <div class="flex-1 min-w-0 pr-4">
                <div class="flex items-center gap-2">
                  <h3 class="font-bold text-white text-sm truncate">{group.name}</h3>
                  <span class={`text-[9px] font-extrabold px-1.5 py-0.5 rounded tracking-wider ${group.severity === "CRITICAL" ? "bg-red-500/10 text-red-500 border border-red-500/20" : group.severity === "HIGH" ? "bg-amber-500/10 text-amber-500 border border-amber-500/20" : "bg-blue-500/10 text-blue-500 border border-blue-500/20"}`}>
                    {group.severity}
                  </span>
                </div>
                <button
                  on:click={() => openPresetDetails(group)}
                  class="text-xs text-accent-blue hover:text-accent-blue-hover font-semibold transition-colors mt-1 hover:underline cursor-pointer border-none bg-transparent"
                >
                  Manage granular rules
                </button>
              </div>

              <!-- Switch -->
              <div class="flex items-center">
                <label class="inline-flex relative items-center cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={isEnabled}
                    on:change={(e) => toggleModule(group.rule_pattern, e.currentTarget.checked)}
                    class="sr-only peer"
                  />
                  <div
                    class="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-800 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-accent-blue"
                  ></div>
                </label>
              </div>
            </Card>
          {/each}
        </div>
      </div>

      <!-- Custom Rules Table -->
      <div class="space-y-4">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-bold text-white flex items-center gap-2">
            <Terminal size={18} class="text-accent-blue" />
            <span>VHost Custom Rules</span>
          </h2>
          <Button
            on:click={() => (showForm = !showForm)}
            variant="secondary"
            className="text-xs py-1.5 px-3 flex items-center gap-1.5"
          >
            {#if showForm}
              <span>Cancel</span>
            {:else}
              <Plus size={14} /> <span>Build Rule</span>
            {/if}
          </Button>
        </div>
        
        <Card className="p-0 overflow-hidden">
          <DataTable
            columns={["ID", "Rule Name", "Condition", "Action", "Enabled", "Active", "Options"]}
          >
            {#if $customRulesList && $customRulesList.length > 0}
              {#each $customRulesList as rule}
                <tr
                  class="hover:bg-slate-900/20 border-b border-border-muted/40 last:border-0 transition-colors {rule.enabled ? '' : 'opacity-40'}"
                >
                  <td class="px-6 py-4 whitespace-nowrap text-accent-blue font-mono text-xs font-bold"
                    >{rule.id}</td
                  >
                  <td class="px-6 py-4 whitespace-nowrap text-text-primary font-bold text-sm">{rule.name}</td>
                  <td class="px-6 py-4 whitespace-nowrap text-text-secondary font-mono text-xs"
                    >{displayCondition(rule)}</td
                  >
                  <td class="px-6 py-4 whitespace-nowrap">
                    <Badge variant={rule.action === "redirect" ? "primary" : "danger"}>
                      {rule.action.toUpperCase()}
                    </Badge>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-center">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      on:change={() => toggleRuleGlobalEnabled(rule.id)}
                      class="rounded border-border-muted bg-slate-950 text-success focus:ring-success cursor-pointer"
                    />
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-center">
                    <input
                      type="checkbox"
                      checked={isRuleBound(rule.id)}
                      on:change={() => toggleCustomRule(rule.id)}
                      class="rounded border-border-muted bg-slate-950 text-accent-blue focus:ring-accent-blue cursor-pointer"
                      disabled={$vhostsList.length === 0}
                    />
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-right">
                    <div class="flex justify-end gap-2">
                      <Button
                        variant="ghost"
                        on:click={() => editRule(rule)}
                        className="p-1.5 text-text-muted hover:text-accent-blue rounded-xl"
                        title="Edit"
                      >
                        <Edit2 size={15} />
                      </Button>
                      <Button
                        variant="ghost"
                        on:click={() => confirmDeleteRule(rule.id)}
                        className="p-1.5 text-text-muted hover:text-error rounded-xl"
                        title="Delete"
                      >
                        <Trash2 size={15} />
                      </Button>
                    </div>
                  </td>
                </tr>
              {/each}
            {:else}
              <tr>
                <td colspan="7" class="px-6 py-12 text-center text-text-muted italic select-none"
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
        <Card className="flex flex-col gap-4 border-accent-blue/30 shadow-glow-blue/5">
          <div class="flex items-center justify-between border-b border-border-muted/80 pb-3">
            <h3 class="font-bold text-white flex items-center gap-2 text-sm uppercase tracking-wider">
              <Terminal size={16} class="text-accent-blue" />
              <span>{editingRuleId ? "Edit Custom Rule" : "New Custom Rule"}</span>
            </h3>
            {#if editingRuleId}
              <Badge variant="primary">{editingRuleId}</Badge>
            {/if}
          </div>

          <div class="space-y-4">
            <Input
              id="custom_rule_name"
              label="Rule Name"
              bind:value={ruleName}
              placeholder="e.g. Block login scanner"
              required={true}
            />

            <div class="grid grid-cols-2 gap-3">
              <div class="space-y-1.5">
                <label for="custom_rule_field" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
                  Target Field
                </label>
                <select
                  id="custom_rule_field"
                  bind:value={conditionFieldType}
                  class="w-full bg-slate-950/50 border border-border-muted rounded-xl px-3 py-2.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue transition-all"
                >
                  <option value="path" class="bg-bg-secondary">URL Path</option>
                  <option value="query" class="bg-bg-secondary">Query Param</option>
                  <option value="body" class="bg-bg-secondary">Request Body</option>
                  <option value="header" class="bg-bg-secondary">HTTP Header</option>
                </select>
              </div>

              <div class="space-y-1.5">
                <label for="custom_rule_op" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
                  Operator
                </label>
                <select
                  id="custom_rule_op"
                  bind:value={operator}
                  class="w-full bg-slate-950/50 border border-border-muted rounded-xl px-3 py-2.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue transition-all"
                >
                  <option value="contains" class="bg-bg-secondary">Contains</option>
                  <option value="equals" class="bg-bg-secondary">Equals exactly</option>
                  <option value="starts_with" class="bg-bg-secondary">Starts with</option>
                </select>
              </div>
            </div>

            {#if conditionFieldType === "header"}
              <Input
                id="custom_rule_header"
                label="Header Name"
                bind:value={customHeaderName}
                placeholder="e.g. User-Agent"
                required={true}
                className="font-mono text-xs"
              />
            {/if}

            <Input
              id="custom_rule_val"
              label="Match Value"
              bind:value={conditionValue}
              placeholder="e.g. /wp-admin"
              required={true}
              className="font-mono text-xs"
            />

            <div class="space-y-1.5 border-t border-border-muted/80 pt-4 mt-2">
              <label for="custom_rule_action" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
                Action
              </label>
              <select
                id="custom_rule_action"
                bind:value={action}
                class="w-full bg-slate-950/50 border border-border-muted rounded-xl px-3 py-2.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue transition-all font-bold"
              >
                <option value="block" class="bg-bg-secondary">Block (403)</option>
                <option value="redirect" class="bg-bg-secondary">Redirect (302)</option>
              </select>
            </div>

            {#if action === "redirect"}
              <Input
                id="custom_rule_redirect"
                label="Redirect URL"
                bind:value={redirectUrl}
                placeholder="http://..."
                required={true}
                className="font-mono text-xs"
              />
            {/if}
          </div>

          <div class="flex gap-3 pt-2">
            <Button
              on:click={cancelEdit}
              variant="secondary"
              className="flex-1"
            >
              Cancel
            </Button>
            <Button
              on:click={handleSaveCustomRule}
              variant="primary"
              className="flex-1"
            >
              Save Rule
            </Button>
          </div>
        </Card>
      {/if}

      <!-- Sandbox -->
      <Card className="flex flex-col gap-4">
        <div class="flex items-center justify-between border-b border-border-muted pb-3">
          <h3 class="font-bold text-white flex items-center gap-2 text-sm uppercase tracking-wider">
            <Play size={16} class="text-success" />
            <span>Sandbox Simulator</span>
          </h3>
        </div>
        <p class="text-xs text-text-secondary">
          Test traffic payloads against active core modules and custom rules instantly.
        </p>

        <div class="relative">
          <textarea
            bind:value={testPayload}
            class="w-full bg-slate-950/50 border border-border-muted rounded-xl p-3 text-xs font-mono text-text-primary focus:outline-none focus:ring-2 focus:ring-success/50 focus:border-success h-28 resize-none transition-colors"
            placeholder="Paste malicious request payload here..."
          ></textarea>
          <Button
            on:click={runSimulation}
            variant="secondary"
            className="absolute bottom-3 right-3 p-2 rounded-lg border border-border-muted shadow-md text-success hover:bg-slate-900/65"
          >
            <Play size={14} />
          </Button>
        </div>

        {#if simulationResult.status === "testing"}
          <div
            class="p-3 bg-slate-950/30 rounded-xl border border-border-muted text-center text-text-secondary text-xs flex justify-center items-center gap-2 animate-pulse"
          >
            <div
              class="w-4 h-4 border-2 border-success border-t-transparent rounded-full animate-spin"
            ></div>
            <span>Running Simulation...</span>
          </div>
        {:else if simulationResult.status === "triggered"}
          <div
            class="p-3 bg-error-bg border border-error/20 rounded-xl flex items-center justify-between"
          >
            <div class="flex items-center gap-2 text-error font-bold text-xs">
              <AlertTriangle size={15} />
              <span>BLOCKED</span>
            </div>
            <span
              class="text-text-secondary text-xs font-mono truncate max-w-[180px] font-bold"
              title={simulationResult.ruleName}>{simulationResult.ruleName}</span
            >
          </div>
        {:else if simulationResult.status === "passed"}
          <div
            class="p-3 bg-success-bg border border-success/20 rounded-xl flex items-center gap-2 text-success font-bold text-xs"
          >
            <CheckCircle size={15} />
            <span>ALLOWED (No triggers)</span>
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
  on:cancel={() => {
    showDeleteModal = false;
    ruleToDelete = null;
  }}
/>

<PresetDetailsModal
  show={showPresetModal}
  preset={selectedPreset}
  activeRules={$vhostsList[selectedVhostIndex]?.rules || []}
  on:close={() => (showPresetModal = false)}
  on:toggleRule={handleToggleGranularRule}
/>
