<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { X, Globe, Shield, Mail } from "lucide-svelte";
  import Input from "./Input.svelte";
  import Button from "./Button.svelte";

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
    class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm"
  >
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div
      class="bg-bg-secondary border border-border-muted rounded-2xl shadow-premium w-full max-w-md overflow-hidden"
      on:click|stopPropagation
    >
      <div class="flex items-center justify-between p-5 border-b border-border-muted/80 bg-slate-900/20">
        <h3 class="text-lg font-bold text-white">Add SSL Certificate</h3>
        <Button
          variant="ghost"
          on:click={close}
          className="p-1.5 rounded-xl hover:bg-slate-800/40"
        >
          <X size={18} />
        </Button>
      </div>

      <div class="p-6 space-y-4">
        <div class="space-y-1">
          <Input
            id="domain-input"
            label="Domain Name"
            bind:value={domain}
            placeholder="e.g. app.example.com"
            required={true}
          />
        </div>

        <div class="space-y-1.5">
          <label for="provider-select" class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
            SSL Provider
          </label>
          <div class="relative">
            <select
              id="provider-select"
              bind:value={provider}
              class="w-full px-4 py-2.5 bg-slate-950/50 border border-border-muted rounded-xl text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue transition-all duration-200"
            >
              <option value="Let's Encrypt" class="bg-bg-secondary">Let's Encrypt (ACME HTTP-01)</option>
              <option value="Local CA" class="bg-bg-secondary">Local Self-Signed CA</option>
            </select>
          </div>
        </div>

        <div class="space-y-1">
          <Input
            id="email-input"
            type="email"
            label="ACME Registration Email"
            bind:value={email}
            disabled={provider !== "Let's Encrypt"}
            placeholder="admin@example.com"
          />
        </div>
      </div>

      <div
        class="flex items-center justify-end gap-3 p-5 border-t border-border-muted bg-slate-900/20"
      >
        <Button
          variant="ghost"
          on:click={close}
        >
          Cancel
        </Button>
        <Button
          variant="primary"
          on:click={submit}
          disabled={isLoading || !domain}
          className="flex items-center gap-2"
        >
          {#if isLoading}
            <div
              class="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin"
            ></div>
            <span>Requesting...</span>
          {:else}
            <span>Request Certificate</span>
          {/if}
        </Button>
      </div>
    </div>
  </div>
{/if}
