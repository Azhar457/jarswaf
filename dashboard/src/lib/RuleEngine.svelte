<script lang="ts">
  import { onMount } from 'svelte';

  export let controllerUrl = '';

  interface CustomRule {
    id: string;
    name: string;
    condition_type: string; // "path", "query", "body", "header:<name>"
    operator: string;       // "equals", "contains", "starts_with"
    condition_value: string;
    action: string;         // "block", "redirect"
    action_value: string;   // Target redirect URL
    enabled: boolean;
  }

  interface VHost {
    name: string;
    hosts: string[];
    backend: string;
    rules: string[];
    blocked_countries: string[];
    geoblock_type: string;
    custom_rules: CustomRule[];
    ssl: string;
    max_body: string;
    rate_limit: string;
  }

  let vhosts: VHost[] = [];
  let selectedVhostIndex = 0;
  
  // Custom Rules editor state
  let ruleName = "";
  let conditionFieldType = "path"; // "path", "query", "body", "header"
  let customHeaderName = "User-Agent";
  let operator = "contains";    // "equals", "contains", "starts_with"
  let conditionValue = "";
  let action = "block";         // "block", "redirect"
  let redirectUrl = "";
  let editingRuleId: string | null = null;

  // Presets info reference
  let presetGroups = [
    {
      key: 'sqli',
      name: "SQL Injection Protection",
      rule_pattern: "SQLI-*",
      icon: "database",
      severity: "CRITICAL",
      rules: [
        { id: "SQLI-001", name: "SQL Injection (Basic)", description: "Classic SQL injection pattern (OR 1=1, UNION SELECT)" },
        { id: "SQLI-002", name: "SQL Injection (Blind/Time)", description: "Time-based blind SQL injection (SLEEP, WAITFOR)" },
        { id: "SQLI-003", name: "SQL Injection (Union)", description: "UNION SELECT queries to extract DB schema" }
      ]
    },
    {
      key: 'xss',
      name: "Cross-Site Scripting (XSS)",
      rule_pattern: "XSS-*",
      icon: "code",
      severity: "HIGH",
      rules: [
        { id: "XSS-001", name: "XSS - Script Tag", description: "Injecting script block or external javascript sources" },
        { id: "XSS-002", name: "XSS - Event Handler", description: "HTML event handlers execution (onload, onerror, alert)" }
      ]
    },
    {
      key: 'lfi',
      name: "File Inclusion Protection",
      rule_pattern: "LFI-*",
      icon: "folder_open",
      severity: "HIGH",
      rules: [
        { id: "LFI-001", name: "Local File Inclusion", description: "Path traversal access (/etc/passwd, ../)" },
        { id: "RFI-001", name: "Remote File Inclusion", description: "External script execution via URL inclusion" }
      ]
    },
    {
      key: 'cmdi',
      name: "OS Command Injection",
      rule_pattern: "CMDI-*",
      icon: "terminal",
      severity: "HIGH",
      rules: [
        { id: "CMDI-001", name: "Command Exec Pattern", description: "Detect shell character execution (;, |, `, $())" }
      ]
    },
    {
      key: 'ssrf',
      name: "Request Forgery Protection",
      rule_pattern: "SSRF-*",
      icon: "swap_calls",
      severity: "MEDIUM",
      rules: [
        { id: "SSRF-001", name: "SSRF localhost bypass", description: "Access local network interfaces or metadata endpoints" }
      ]
    },
    {
      key: 'bot',
      name: "Bots & Scanners Filter",
      rule_pattern: "BOT-*",
      icon: "smart_toy",
      severity: "MEDIUM",
      rules: [
        { id: "BOT-001", name: "Bad User-Agent", description: "Known security scanners (sqlmap, nmap, gobuster, wfuzz)" }
      ]
    }
  ];

  // Sandbox simulation state
  let testPayload = "";
  let simulationResult: { status: 'idle' | 'testing' | 'triggered' | 'passed', ruleName?: string } = { status: 'idle' };

  async function fetchVhosts() {
    try {
      const res = await fetch(`${controllerUrl}/api/v1/vhosts`);
      if (res.ok) {
        vhosts = await res.json();
      }
    } catch (e) {
      console.error("Failed to fetch virtual hosts:", e);
    }
  }

  async function saveVhosts() {
    try {
      const res = await fetch(`${controllerUrl}/api/v1/vhosts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(vhosts)
      });
      if (res.ok) {
        await fetchVhosts();
      }
    } catch (e) {
      console.error("Failed to save custom rules:", e);
    }
  }

  onMount(() => {
    fetchVhosts();
  });

  // Toggle rule modules
  async function toggleModule(pattern: string, checked: boolean) {
    if (vhosts.length === 0) return;
    const host = vhosts[selectedVhostIndex];
    let activeRules = [...(host.rules || [])];
    
    if (checked) {
      if (!activeRules.includes(pattern)) {
        activeRules.push(pattern);
      }
      // Specific to LFI: enable RFI as well
      if (pattern === 'LFI-*' && !activeRules.includes('RFI-*')) {
        activeRules.push('RFI-*');
      }
    } else {
      activeRules = activeRules.filter(r => r !== pattern);
      if (pattern === 'LFI-*') {
        activeRules = activeRules.filter(r => r !== 'RFI-*');
      }
    }
    
    vhosts[selectedVhostIndex].rules = activeRules;
    await saveVhosts();
  }

  function handleSaveCustomRule() {
    if (vhosts.length === 0) return;
    if (!ruleName || !conditionValue) return;
    if (action === 'redirect' && !redirectUrl) return;

    let finalConditionType = conditionFieldType;
    if (conditionFieldType === 'header') {
      finalConditionType = `header:${customHeaderName.trim().toLowerCase()}`;
    }

    const currentVhost = vhosts[selectedVhostIndex];
    if (!currentVhost.custom_rules) {
      currentVhost.custom_rules = [];
    }

    if (editingRuleId) {
      // Modify existing
      currentVhost.custom_rules = currentVhost.custom_rules.map(r => {
        if (r.id === editingRuleId) {
          return {
            ...r,
            name: ruleName,
            condition_type: finalConditionType,
            operator: operator,
            condition_value: conditionValue,
            action: action,
            action_value: action === 'redirect' ? redirectUrl : ""
          };
        }
        return r;
      });
    } else {
      // Create new
      const newRule: CustomRule = {
        id: "CR-" + Math.floor(100 + Math.random() * 900),
        name: ruleName,
        condition_type: finalConditionType,
        operator: operator,
        condition_value: conditionValue,
        action: action,
        action_value: action === 'redirect' ? redirectUrl : "",
        enabled: true
      };
      currentVhost.custom_rules.push(newRule);
    }

    vhosts = [...vhosts];
    saveVhosts();

    // Reset Form
    cancelEdit();
  }

  function editRule(rule: CustomRule) {
    editingRuleId = rule.id;
    ruleName = rule.name;
    
    if (rule.condition_type.startsWith('header:')) {
      conditionFieldType = 'header';
      customHeaderName = rule.condition_type.replace('header:', '');
    } else {
      conditionFieldType = rule.condition_type;
    }
    
    operator = rule.operator;
    conditionValue = rule.condition_value;
    action = rule.action;
    redirectUrl = rule.action_value;
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
  }

  async function toggleCustomRule(ruleId: string) {
    if (vhosts.length === 0) return;
    vhosts[selectedVhostIndex].custom_rules = vhosts[selectedVhostIndex].custom_rules.map(r => {
      if (r.id === ruleId) {
        return { ...r, enabled: !r.enabled };
      }
      return r;
    });
    vhosts = [...vhosts];
    await saveVhosts();
  }

  async function deleteCustomRule(ruleId: string) {
    if (!confirm("Are you sure you want to delete this custom rule?")) return;
    vhosts[selectedVhostIndex].custom_rules = vhosts[selectedVhostIndex].custom_rules.filter(r => r.id !== ruleId);
    vhosts = [...vhosts];
    await saveVhosts();
  }

  function displayCondition(rule: CustomRule): string {
    let field = rule.condition_type;
    if (field.startsWith('header:')) {
      field = `Header [${field.substring(7).toUpperCase()}]`;
    } else {
      field = field.toUpperCase();
    }
    
    let op = rule.operator;
    if (op === 'contains') op = 'contains';
    else if (op === 'equals') op = '=';
    else if (op === 'starts_with') op = 'starts with';

    return `${field} ${op} "${rule.condition_value}"`;
  }

  // Sandbox simulation test
  function runSimulation() {
    if (!testPayload) return;
    simulationResult = { status: 'testing' };

    setTimeout(() => {
      const payloadLower = testPayload.toLowerCase();
      
      // Test default modules
      const host = vhosts[selectedVhostIndex];
      const activeRules = host ? (host.rules || []) : [];

      if (activeRules.includes("SQLI-*") && (payloadLower.includes("union select") || payloadLower.includes("select ") || payloadLower.includes("or 1=1"))) {
        simulationResult = { status: 'triggered', ruleName: 'SQL Injection Module (SQLI-*)' };
        return;
      }

      if (activeRules.includes("XSS-*") && (payloadLower.includes("<script") || payloadLower.includes("javascript:") || payloadLower.includes("onload="))) {
        simulationResult = { status: 'triggered', ruleName: 'Cross-Site Scripting Module (XSS-*)' };
        return;
      }

      if (activeRules.includes("LFI-*") && (payloadLower.includes("../") || payloadLower.includes("etc/passwd") || payloadLower.includes("boot.ini"))) {
        simulationResult = { status: 'triggered', ruleName: 'File Inclusion Module (LFI-*)' };
        return;
      }

      if (activeRules.includes("CMDI-*") && (payloadLower.includes("; rm ") || payloadLower.includes("&& wget") || payloadLower.includes("curl "))) {
        simulationResult = { status: 'triggered', ruleName: 'OS Command Injection Module (CMDI-*)' };
        return;
      }

      // Test custom rules
      const activeCustomRules = host ? (host.custom_rules || []).filter(r => r.enabled) : [];
      for (const rule of activeCustomRules) {
        let isMatch = false;
        const val = payloadLower;
        const matchVal = rule.condition_value.toLowerCase();
        
        if (rule.operator === 'equals') {
          isMatch = (val === matchVal);
        } else if (rule.operator === 'starts_with') {
          isMatch = val.startsWith(matchVal);
        } else {
          isMatch = val.includes(matchVal);
        }

        if (isMatch) {
          simulationResult = { status: 'triggered', ruleName: `Custom Rule [${rule.name}]` };
          return;
        }
      }

      simulationResult = { status: 'passed' };
    }, 800);
  }
</script>

<!-- Domain Selection Bar -->
<div class="glass-panel p-4 rounded-xl flex items-center justify-between border border-outline-variant mb-6 bg-surface-container-low/50">
  <div class="flex items-center gap-4">
    <span class="material-symbols-outlined text-primary">dns</span>
    <span class="text-xs font-bold text-outline uppercase tracking-wider">Select virtual host:</span>
    {#if vhosts.length > 0}
      <select bind:value={selectedVhostIndex} class="bg-surface-container border border-outline-variant rounded px-sm py-1 text-sm outline-none focus:border-primary text-primary font-bold cursor-pointer">
        {#each vhosts as host, index}
          <option value={index}>{host.hosts[0]} ({host.name})</option>
        {/each}
      </select>
    {:else}
      <span class="text-xs font-mono text-error">No virtual hosts available</span>
    {/if}
  </div>
</div>

<div class="flex flex-col lg:flex-row gap-6 h-[calc(100vh-240px)] overflow-hidden">
  <!-- Left panel: Rule Lists & Toggles -->
  <div class="flex-grow flex flex-col gap-6 overflow-y-auto no-scrollbar pr-1">
    <!-- Title -->
    <div>
      <h2 class="font-headline-md text-headline-md text-on-surface">Active Policy Engine</h2>
      <p class="text-on-surface-variant font-body-sm text-body-sm">Configure preset protection modules and user-defined custom logic rules.</p>
    </div>

    <!-- Preset Modules Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      {#each presetGroups as group}
        {@const hostRules = vhosts[selectedVhostIndex] ? (vhosts[selectedVhostIndex].rules || []) : []}
        {@const isEnabled = hostRules.includes(group.rule_pattern)}
        <div class="glass-card rounded-xl p-4 border border-outline-variant/60 relative overflow-hidden flex flex-col gap-2">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-sm">
              <span class="material-symbols-outlined text-primary text-xl">{group.icon}</span>
              <div>
                <h4 class="font-bold text-sm text-on-surface">{group.name}</h4>
                <p class="text-[11px] text-on-surface-variant">{group.rules.length} static signatures active</p>
              </div>
            </div>
            
            <div class="flex items-center gap-2">
              <span class="text-[9px] font-mono px-1.5 py-0.5 rounded border {group.severity === 'CRITICAL' ? 'bg-error/10 text-error border-error/20' : group.severity === 'HIGH' ? 'bg-tertiary-container/10 text-tertiary-container border-tertiary-container/20' : 'bg-on-surface-variant/10 text-on-surface-variant border-on-surface-variant/20'}">
                {group.severity}
              </span>
              <label class="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={isEnabled} 
                  on:change={(e) => toggleModule(group.rule_pattern, e.currentTarget.checked)}
                  class="sr-only peer"
                />
                <div class="w-9 h-5 bg-surface-container-highest rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>
          </div>

          <div class="space-y-1 pl-6 pt-1 border-t border-outline-variant/20">
            {#each group.rules as r}
              <div class="flex items-baseline justify-between text-xs py-0.5">
                <span class="font-mono text-primary text-[10px] bg-primary/5 px-1 rounded border border-primary/10">{r.id}</span>
                <span class="text-on-surface-variant text-[11px] flex-1 ml-sm truncate" title={r.description}>{r.name}</span>
                <span class="text-[10px] text-outline">BLOCK</span>
              </div>
            {/each}
          </div>
        </div>
      {/each}
    </div>

    <!-- Custom Rules Section -->
    <div class="glass-card rounded-xl p-md border border-outline-variant/60 flex flex-col gap-sm">
      <div class="flex justify-between items-center pb-xs border-b border-outline-variant/30">
        <div class="flex items-center gap-sm">
          <span class="material-symbols-outlined text-primary">edit_note</span>
          <h3 class="font-bold text-sm text-on-surface">Custom Request Filters</h3>
        </div>
        <button 
          on:click={cancelEdit}
          class="text-xs px-2 py-1 bg-surface-container border border-outline-variant rounded hover:bg-surface-container-high transition-all cursor-pointer font-bold border-none text-on-surface"
        >
          Reset Builder
        </button>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse text-xs">
          <thead>
            <tr class="border-b border-outline-variant">
              <th class="py-sm px-md text-outline font-bold uppercase tracking-wider">ID</th>
              <th class="py-sm px-md text-outline font-bold uppercase tracking-wider">Rule Name</th>
              <th class="py-sm px-md text-outline font-bold uppercase tracking-wider">Condition Match</th>
              <th class="py-sm px-md text-outline font-bold uppercase tracking-wider">Action</th>
              <th class="py-sm px-md text-outline font-bold uppercase tracking-wider text-center">Active</th>
              <th class="py-sm px-md text-outline font-bold uppercase tracking-wider text-right">Options</th>
            </tr>
          </thead>
          <tbody>
            {#if vhosts[selectedVhostIndex] && vhosts[selectedVhostIndex].custom_rules && vhosts[selectedVhostIndex].custom_rules.length > 0}
              {#each vhosts[selectedVhostIndex].custom_rules as rule}
                <tr class="border-b border-outline-variant/20 hover:bg-surface-container-high/30 transition-colors {!rule.enabled ? 'opacity-50' : ''}">
                  <td class="py-sm px-md font-mono text-primary font-bold">{rule.id}</td>
                  <td class="py-sm px-md text-on-surface font-semibold">{rule.name}</td>
                  <td class="py-sm px-md font-mono text-on-surface-variant">{displayCondition(rule)}</td>
                  <td class="py-sm px-md">
                    {#if rule.action === 'redirect'}
                      <span class="px-1.5 py-0.5 bg-primary/10 border border-primary/20 text-primary text-[10px] font-bold rounded uppercase tracking-wider font-mono" title={rule.action_value}>
                        REDIRECT
                      </span>
                    {:else}
                      <span class="px-1.5 py-0.5 bg-error/10 border border-error/20 text-error text-[10px] font-bold rounded uppercase tracking-wider font-mono">
                        BLOCK (403)
                      </span>
                    {/if}
                  </td>
                  <td class="py-sm px-md text-center">
                    <input 
                      type="checkbox" 
                      checked={rule.enabled} 
                      on:change={() => toggleCustomRule(rule.id)}
                      class="rounded border-outline-variant text-primary focus:ring-0 cursor-pointer"
                    />
                  </td>
                  <td class="py-sm px-md text-right">
                    <div class="flex justify-end gap-1.5">
                      <button on:click={() => editRule(rule)} class="text-on-surface-variant hover:text-primary transition-colors cursor-pointer bg-transparent border-none" title="Edit Rule">
                        <span class="material-symbols-outlined text-[16px]">edit</span>
                      </button>
                      <button on:click={() => deleteCustomRule(rule.id)} class="text-on-surface-variant hover:text-error transition-colors cursor-pointer bg-transparent border-none" title="Delete Rule">
                        <span class="material-symbols-outlined text-[16px]">delete</span>
                      </button>
                    </div>
                  </td>
                </tr>
              {/each}
            {:else}
              <tr>
                <td colspan="6" class="py-6 text-center text-outline font-mono">
                  No custom rules defined for this host. Use the right panel to define one.
                </td>
              </tr>
            {/if}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Right panel: Custom Rule Builder & Simulation Sandbox -->
  <div class="w-full lg:w-[420px] flex-shrink-0 flex flex-col gap-6 overflow-y-auto no-scrollbar">
    <!-- Rule Editor Panel -->
    <div class="glass-card rounded-xl border border-outline-variant/60 flex flex-col overflow-hidden">
      <div class="p-4 border-b border-outline-variant flex items-center justify-between bg-surface-container-high/30">
        <div class="flex items-center gap-2">
          <span class="material-symbols-outlined text-primary text-lg">terminal</span>
          <span class="font-bold text-sm tracking-tight text-on-surface">CUSTOM RULE BUILDER</span>
        </div>
        {#if editingRuleId}
          <span class="text-[10px] font-mono bg-primary/20 text-primary px-1.5 rounded uppercase font-bold">Editing: {editingRuleId}</span>
        {/if}
      </div>

      <div class="p-4 space-y-4 flex-1">
        <div class="flex flex-col gap-1">
          <label for="rule_name_inp" class="text-[10px] uppercase tracking-widest text-on-surface-variant font-bold">Rule Name / Description</label>
          <input 
            id="rule_name_inp" 
            class="w-full bg-[#040508] border border-outline-variant rounded px-3 py-2 text-sm text-on-surface focus:border-primary outline-none" 
            type="text" 
            placeholder="e.g. Block login page scanner"
            bind:value={ruleName}
          />
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div class="flex flex-col gap-1">
            <label for="field_select" class="text-[10px] uppercase tracking-widest text-on-surface-variant font-bold">Target Field</label>
            <select id="field_select" bind:value={conditionFieldType} class="w-full bg-[#040508] border border-outline-variant rounded px-3 py-2 text-sm outline-none focus:border-primary text-on-surface">
              <option value="path">URL Path (e.g. /wp-admin)</option>
              <option value="query">Query Parameter</option>
              <option value="body">Request Body</option>
              <option value="header">HTTP Header</option>
            </select>
          </div>

          <div class="flex flex-col gap-1">
            <label for="operator_select" class="text-[10px] uppercase tracking-widest text-on-surface-variant font-bold">Operator</label>
            <select id="operator_select" bind:value={operator} class="w-full bg-[#040508] border border-outline-variant rounded px-3 py-2 text-sm outline-none focus:border-primary text-on-surface">
              <option value="contains">Contains substring</option>
              <option value="equals">Equals exactly</option>
              <option value="starts_with">Starts with prefix</option>
            </select>
          </div>
        </div>

        {#if conditionFieldType === 'header'}
          <div class="flex flex-col gap-1">
            <label for="hdr_name" class="text-[10px] uppercase tracking-widest text-on-surface-variant font-bold">HTTP Header Name</label>
            <input 
              id="hdr_name" 
              class="w-full bg-[#040508] border border-outline-variant rounded px-3 py-2 text-sm text-on-surface focus:border-primary outline-none font-mono" 
              type="text" 
              placeholder="e.g. User-Agent or Referer"
              bind:value={customHeaderName}
            />
          </div>
        {/if}

        <div class="flex flex-col gap-1">
          <label for="match_val" class="text-[10px] uppercase tracking-widest text-on-surface-variant font-bold">Value to Match</label>
          <input 
            id="match_val" 
            class="w-full bg-[#040508] border border-outline-variant rounded px-3 py-2 text-sm text-on-surface focus:border-primary outline-none font-mono" 
            type="text" 
            placeholder="e.g. /wp-admin"
            bind:value={conditionValue}
          />
        </div>

        <div class="grid grid-cols-2 gap-3 border-t border-outline-variant/30 pt-4">
          <div class="flex flex-col gap-1 col-span-2">
            <label for="action_sel" class="text-[10px] uppercase tracking-widest text-on-surface-variant font-bold">Enforcement Action</label>
            <select id="action_sel" bind:value={action} class="w-full bg-[#040508] border border-outline-variant rounded px-3 py-2 text-sm outline-none focus:border-primary text-on-surface font-bold">
              <option value="block">Block request (Return 403 Forbidden)</option>
              <option value="redirect">Redirect client (Return 302 Redirect)</option>
            </select>
          </div>
          
          {#if action === 'redirect'}
            <div class="flex flex-col gap-1 col-span-2">
              <label for="redir_url" class="text-[10px] uppercase tracking-widest text-on-surface-variant font-bold">Target Redirect URL</label>
              <input 
                id="redir_url" 
                class="w-full bg-[#040508] border border-outline-variant rounded px-3 py-2 text-sm text-on-surface focus:border-primary outline-none font-mono" 
                type="text" 
                placeholder="e.g. http://localhost/blocked"
                bind:value={redirectUrl}
              />
            </div>
          {/if}
        </div>
      </div>

      <div class="p-4 bg-surface-container-high/30 border-t border-outline-variant flex items-center justify-between">
        {#if editingRuleId}
          <button on:click={cancelEdit} class="text-xs text-outline hover:text-on-surface transition-colors cursor-pointer bg-transparent border-none">Cancel</button>
        {:else}
          <span class="text-xs text-on-surface-variant italic font-mono">New Signature</span>
        {/if}
        <button 
          on:click={handleSaveCustomRule}
          class="bg-primary text-background font-bold px-6 py-2 rounded text-xs transition-transform active:scale-95 shadow-lg shadow-primary/10 cursor-pointer border-none"
        >
          {editingRuleId ? 'Apply Updates' : 'Compile & Add Rule'}
        </button>
      </div>
    </div>

    <!-- Simulation Sandbox -->
    <div class="glass-card rounded-xl p-4 border border-outline-variant/60">
      <div class="flex items-center gap-2 mb-4 pb-1 border-b border-outline-variant/30">
        <span class="material-symbols-outlined text-primary text-md">science</span>
        <h4 class="font-bold text-sm tracking-tight text-on-surface">SIMULATION SANDBOX</h4>
      </div>
      <div class="space-y-4">
        <p class="text-[11px] text-on-surface-variant">Test payloads or paths against active modules and custom rules instantly:</p>
        
        <div class="relative">
          <textarea 
            class="w-full bg-[#040508] border border-outline-variant rounded p-3 text-xs font-mono text-on-surface focus:border-primary outline-none h-20 resize-none" 
            placeholder="Paste malicious payload or URL here (e.g. /wp-admin or ' OR 1=1)..."
            bind:value={testPayload}
          ></textarea>
          <button 
            on:click={runSimulation}
            class="absolute bottom-3 right-3 bg-surface-container-highest p-1.5 rounded hover:text-primary transition-colors cursor-pointer text-xs flex items-center gap-1 border-none text-on-surface-variant"
            title="Execute test"
          >
            <span class="material-symbols-outlined text-sm">play_arrow</span>
            <span>Test</span>
          </button>
        </div>

        {#if simulationResult.status === 'testing'}
          <div class="flex items-center justify-center p-3 rounded bg-surface-container/30 border border-outline-variant">
            <span class="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin mr-2"></span>
            <span class="text-xs font-mono text-outline">Simulating enforcements...</span>
          </div>
        {:else}
          {#if simulationResult.status === 'triggered'}
            <div class="flex items-center justify-between p-3 rounded bg-error/10 border border-error/20">
              <div class="flex items-center gap-2">
                <span class="material-symbols-outlined text-error text-md">dangerous</span>
                <span class="text-xs font-bold text-error">DETECTION TRIGGERED</span>
              </div>
              <span class="text-[10px] font-mono text-on-surface-variant max-w-[180px] truncate" title={simulationResult.ruleName}>
                Rule: {simulationResult.ruleName}
              </span>
            </div>
          {:else if simulationResult.status === 'passed'}
            <div class="flex items-center justify-between p-3 rounded bg-primary/10 border border-primary/20">
              <div class="flex items-center gap-2">
                <span class="material-symbols-outlined text-primary text-md">check_circle</span>
                <span class="text-xs font-bold text-primary font-mono">REQUEST CLEARED</span>
              </div>
              <span class="text-[10px] font-mono text-on-surface-variant">No rules triggered</span>
            </div>
          {/if}
        {/if}
      </div>
    </div>
  </div>
</div>

<style>
  .glass-card {
    background: rgba(13, 17, 23, 0.7);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-top: 1px solid rgba(255, 255, 255, 0.15);
  }

  .glass-panel {
    background: #0d1117;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-top: 1px solid rgba(255, 255, 255, 0.12);
    position: relative;
  }
</style>
