<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let editingRuleId: string | null = null;
  export let ruleName = "";
  export let conditionFieldType = "path";
  export let operator = "contains";
  export let customHeaderName = "User-Agent";
  export let conditionValue = "";
  export let action = "block";
  export let redirectUrl = "";

  const dispatch = createEventDispatcher<{
    save: void;
    cancel: void;
  }>();

  function handleSave() {
    if (!ruleName || !conditionValue) return;
    if (action === 'redirect' && !redirectUrl) return;
    dispatch('save');
  }

  function handleCancel() {
    dispatch('cancel');
  }
</script>

<div class="glass-card rounded-xl border border-outline-variant/60 flex flex-col overflow-hidden">
  <div class="p-4 border-b border-outline-variant flex items-center justify-between bg-surface-container-high/30">
    <div class="flex items-center ">
      <span class="material-symbols-outlined text-primary text-md">terminal</span>
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
      <button on:click={handleCancel} class="text-xs text-outline hover:text-on-surface transition-colors cursor-pointer bg-transparent border-none">Cancel</button>
    {:else}
      <span class="text-xs text-on-surface-variant italic font-mono">New Signature</span>
    {/if}
    <button 
      on:click={handleSave}
      class="bg-primary text-background font-bold px-6 py-2 rounded text-xs transition-transform active:scale-95 shadow-lg shadow-primary/10 cursor-pointer border-none"
    >
      {editingRuleId ? 'Apply Updates' : 'Compile & Add Rule'}
    </button>
  </div>
</div>

<style>
  .glass-card {
    background: rgba(13, 17, 23, 0.7);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-top: 1px solid rgba(255, 255, 255, 0.15);
  }
</style>
