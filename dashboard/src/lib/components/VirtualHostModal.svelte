<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let show = false;
  export let isEditing = false;
  export let serverName = "";
  export let upstream = "";
  export let ssl = "Auto (Local CA)";
  export let maxBody = "10MB";
  export let rateLimit = "600 req/min";
  export let selectedCategories = {
    sqli: true,
    xss: true,
    lfi: true,
    cmdi: false,
    ssrf: false,
    bot: false
  };
  export let blockedCountries: string[] = [];
  export let geoblockType = "Blocklist";

  const availableCountries = [
    { code: 'US', name: 'United States', flag: '🇺🇸' },
    { code: 'CN', name: 'China', flag: '🇨🇳' },
    { code: 'RU', name: 'Russia', flag: '🇷🇺' },
    { code: 'DE', name: 'Germany', flag: '🇩🇪' },
    { code: 'SG', name: 'Singapore', flag: '🇸🇬' },
    { code: 'ID', name: 'Indonesia', flag: '🇮🇩' },
    { code: 'BR', name: 'Brazil', flag: '🇧🇷' },
    { code: 'AU', name: 'Australia', flag: '🇦🇺' }
  ];

  const dispatch = createEventDispatcher<{
    close: void;
    save: void;
  }>();

  function toggleCountry(code: string, checked: boolean) {
    if (checked) {
      blockedCountries = [...blockedCountries, code];
    } else {
      blockedCountries = blockedCountries.filter(c => c !== code);
    }
  }

  function handleSave() {
    if (!serverName || !upstream) return;
    dispatch('save');
  }

  function handleClose() {
    dispatch('close');
  }

  function handleBackdropClick(e: MouseEvent) {
    if (e.target === e.currentTarget) {
      handleClose();
    }
  }
</script>

{#if show}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div 
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-6 overflow-y-auto"
    on:click={handleBackdropClick}
  >
    <div class="glass-panel rounded-2xl w-full max-w-[680px] p-6 shadow-2xl flex flex-col gap-5 my-auto border border-outline-variant">
      <!-- Header -->
      <div class="flex justify-between items-center border-b border-outline-variant/30 pb-4">
        <h3 class="font-headline-md text-xl font-bold text-on-surface">
          {isEditing ? 'Edit Virtual Host' : 'Create Virtual Host'}
        </h3>
        <button 
          on:click={handleClose} 
          type="button"
          class="text-on-surface-variant/70 hover:text-primary transition-colors cursor-pointer bg-transparent border-none flex items-center justify-center p-1.5 rounded-full hover:bg-white/5"
        >
          <span class="material-symbols-outlined text-xl">close</span>
        </button>
      </div>
      
      <!-- Form Content -->
      <div class="grid grid-cols-2 gap-4 max-h-[70vh] overflow-y-auto pr-1">
        <div class="flex flex-col gap-1.5 col-span-2">
          <label for="server_name" class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">Server Name (Domain / Wildcard)</label>
          <input 
            id="server_name"
            type="text" 
            placeholder="e.g. example.com or *.example.com" 
            bind:value={serverName}
            class="bg-surface-container-low border border-outline-variant rounded-lg p-3 text-sm outline-none focus:border-primary text-on-surface transition-all focus:ring-1 focus:ring-primary/20"
          />
        </div>

        <div class="flex flex-col gap-1.5">
          <label for="upstream" class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">Upstream Backend Port / Host</label>
          <input 
            id="upstream"
            type="text" 
            placeholder="e.g. 127.0.0.1:8080" 
            bind:value={upstream}
            class="bg-surface-container-low border border-outline-variant rounded-lg p-3 text-sm outline-none focus:border-primary text-on-surface font-mono transition-all focus:ring-1 focus:ring-primary/20"
          />
        </div>

        <div class="flex flex-col gap-1.5">
          <label for="ssl" class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">SSL Encryption Mode</label>
          <select 
            id="ssl" 
            bind:value={ssl} 
            class="bg-surface-container-low border border-outline-variant rounded-lg p-3 text-sm outline-none focus:border-primary text-on-surface transition-all focus:ring-1 focus:ring-primary/20"
          >
            <option value="Auto (Local CA)">Auto (Local CA)</option>
            <option value="Manual Cert">Manual Certificate</option>
            <option value="Disabled">Disabled (HTTP Only)</option>
          </select>
        </div>

        <div class="flex flex-col gap-1.5">
          <label for="max_body" class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">Max Request Body Size</label>
          <input 
            id="max_body"
            type="text" 
            placeholder="e.g. 10MB" 
            bind:value={maxBody}
            class="bg-surface-container-low border border-outline-variant rounded-lg p-3 text-sm outline-none focus:border-primary text-on-surface font-mono transition-all focus:ring-1 focus:ring-primary/20"
          />
        </div>

        <div class="flex flex-col gap-1.5">
          <label for="rate_limit" class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">Rate Limiter Threshold</label>
          <input 
            id="rate_limit"
            type="text" 
            placeholder="e.g. 600 req/min" 
            bind:value={rateLimit}
            class="bg-surface-container-low border border-outline-variant rounded-lg p-3 text-sm outline-none focus:border-primary text-on-surface font-mono transition-all focus:ring-1 focus:ring-primary/20"
          />
        </div>

        <!-- WAF Rule modules batch checklist -->
        <div class="col-span-2 border-t border-outline-variant/30 pt-4 mt-2">
          <span class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider block mb-3">Enable WAF Rule Modules</span>
          <div class="grid grid-cols-3 gap-3">
            <label class="flex items-center  cursor-pointer bg-surface-container-low border border-outline-variant rounded-lg p-3 hover:border-primary transition-all text-on-surface">
              <input type="checkbox" bind:checked={selectedCategories.sqli} class="rounded border-outline-variant text-primary focus:ring-0 cursor-pointer" />
              <span class="text-xs">SQL Injection</span>
            </label>
            <label class="flex items-center  cursor-pointer bg-surface-container-low border border-outline-variant rounded-lg p-3 hover:border-primary transition-all text-on-surface">
              <input type="checkbox" bind:checked={selectedCategories.xss} class="rounded border-outline-variant text-primary focus:ring-0 cursor-pointer" />
              <span class="text-xs">XSS Protection</span>
            </label>
            <label class="flex items-center  cursor-pointer bg-surface-container-low border border-outline-variant rounded-lg p-3 hover:border-primary transition-all text-on-surface">
              <input type="checkbox" bind:checked={selectedCategories.lfi} class="rounded border-outline-variant text-primary focus:ring-0 cursor-pointer" />
              <span class="text-xs">Local/Remote File</span>
            </label>
            <label class="flex items-center  cursor-pointer bg-surface-container-low border border-outline-variant rounded-lg p-3 hover:border-primary transition-all text-on-surface">
              <input type="checkbox" bind:checked={selectedCategories.cmdi} class="rounded border-outline-variant text-primary focus:ring-0 cursor-pointer" />
              <span class="text-xs">Command Injection</span>
            </label>
            <label class="flex items-center  cursor-pointer bg-surface-container-low border border-outline-variant rounded-lg p-3 hover:border-primary transition-all text-on-surface">
              <input type="checkbox" bind:checked={selectedCategories.ssrf} class="rounded border-outline-variant text-primary focus:ring-0 cursor-pointer" />
              <span class="text-xs">SSRF Protection</span>
            </label>
            <label class="flex items-center  cursor-pointer bg-surface-container-low border border-outline-variant rounded-lg p-3 hover:border-primary transition-all text-on-surface">
              <input type="checkbox" bind:checked={selectedCategories.bot} class="rounded border-outline-variant text-primary focus:ring-0 cursor-pointer" />
              <span class="text-xs">Bot Scanners</span>
            </label>
          </div>
        </div>

        <!-- Geoblocking strategy -->
        <div class="col-span-2 border-t border-outline-variant/30 pt-4 mt-2 flex flex-col gap-3">
          <div class="flex justify-between items-center">
            <span class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider block">Geoblocking Configuration</span>
            <div class="flex items-center  text-on-surface-variant">
              <span class="text-xs">Strategy:</span>
              <select bind:value={geoblockType} class="bg-surface-container border border-outline-variant rounded px-2.5 py-1 text-xs outline-none focus:border-primary text-on-surface font-bold">
                <option value="Blocklist">Blocklist (Block selected, allow others)</option>
                <option value="Allowlist">Allowlist (Allow selected, block others)</option>
              </select>
            </div>
          </div>
          
          <div class="grid grid-cols-4 ">
            {#each availableCountries as country}
              <label class="flex items-center  cursor-pointer bg-surface-container-low border border-outline-variant rounded-lg p-2.5 hover:border-primary transition-all text-on-surface">
                <input
                  type="checkbox"
                  value={country.code}
                  checked={blockedCountries.includes(country.code)}
                  on:change={(e) => toggleCountry(country.code, (e.target as HTMLInputElement).checked)}
                  class="rounded border-outline-variant text-primary focus:ring-0 cursor-pointer"
                />
                <span class="text-xs flex items-center gap-1">
                  <span>{country.flag}</span>
                  <span>{country.name}</span>
                </span>
              </label>
            {/each}
          </div>
        </div>
      </div>

      <!-- Action Buttons -->
      <div class="flex justify-end gap-3 border-t border-outline-variant/30 pt-4 mt-2">
        <button 
          type="button"
          on:click={handleClose} 
          class="px-5 py-2.5 bg-surface-container border border-outline-variant hover:bg-surface-container-high rounded-lg text-sm text-on-surface font-semibold transition-colors cursor-pointer"
        >
          Cancel
        </button>
        <button 
          type="button"
          on:click={handleSave} 
          class="px-5 py-2.5 bg-primary text-background font-bold rounded-lg text-sm hover:brightness-110 active:scale-95 transition-all cursor-pointer border-none flex items-center gap-1.5 shadow-[0_0_12px_rgba(168,232,255,0.2)]"
        >
          <span class="material-symbols-outlined text-sm font-bold">check</span>
          {isEditing ? 'Save Changes' : 'Create Host'}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .glass-panel {
    background: rgba(13, 17, 23, 0.85);
    backdrop-filter: blur(16px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-top: 1px solid rgba(255, 255, 255, 0.15);
  }
</style>
