<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { X, Globe, Shield, Mail } from "lucide-svelte";

  export let show = false;

  let domain = "";
  let provider = "Let's Encrypt";
  let email = "admin@jarswafwaf.local";
  let isLoading = false;

  const dispatch = createEventDispatcher();

  function close() {
    domain = "";
    provider = "Let's Encrypt";
    email = "admin@jarswafwaf.local";
    show = false;
    dispatch("close");
  }

  function submit() {
    if (!domain) return;
    isLoading = true;
    dispatch("submit", {
      domain,
      provider,
      email,
    });
  }

  // This helps reset the loading state if the parent component finishes the request
  export function resetLoading() {
    isLoading = false;
  }
</script>

{#if show}
  <div
    class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200"
  >
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div
      class="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl w-full max-w-md overflow-hidden animate-in zoom-in-95 duration-200"
      on:click|stopPropagation
    >
      <div class="flex items-center justify-between p-4 border-b border-slate-800 bg-slate-900/50">
        <h3 class="text-lg font-bold text-slate-200">Add SSL Certificate</h3>
        <button
          on:click={close}
          class="p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
        >
          <X size={18} />
        </button>
      </div>

      <div class="p-6 space-y-4">
        <div class="space-y-2">
          <label class="text-sm font-medium text-slate-300 flex items-center gap-2">
            <Globe size={14} class="text-blue-400" /> Domain Name
          </label>
          <input
            type="text"
            bind:value={domain}
            placeholder="e.g. app.example.com"
            class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all placeholder:text-slate-600"
          />
        </div>

        <div class="space-y-2">
          <label class="text-sm font-medium text-slate-300 flex items-center gap-2">
            <Shield size={14} class="text-emerald-400" /> SSL Provider
          </label>
          <select
            bind:value={provider}
            class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-all appearance-none"
          >
            <option value="Let's Encrypt">Let's Encrypt (ACME HTTP-01)</option>
            <option value="Local CA">Local Self-Signed CA</option>
          </select>
        </div>

        <div class="space-y-2">
          <label class="text-sm font-medium text-slate-300 flex items-center gap-2">
            <Mail size={14} class="text-amber-400" /> ACME Registration Email
          </label>
          <input
            type="email"
            bind:value={email}
            disabled={provider !== "Let's Encrypt"}
            placeholder="admin@example.com"
            class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-all placeholder:text-slate-600 disabled:opacity-50 disabled:cursor-not-allowed"
          />
        </div>
      </div>

      <div
        class="flex items-center justify-end gap-3 p-4 border-t border-slate-800 bg-slate-900/50"
      >
        <button
          on:click={close}
          class="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white transition-colors"
        >
          Cancel
        </button>
        <button
          on:click={submit}
          disabled={isLoading || !domain}
          class="px-4 py-2 text-sm font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_15px_rgba(37,99,235,0.3)]"
        >
          {#if isLoading}
            <div
              class="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin"
            ></div>
            Requesting...
          {:else}
            Request Certificate
          {/if}
        </button>
      </div>
    </div>
  </div>
{/if}
