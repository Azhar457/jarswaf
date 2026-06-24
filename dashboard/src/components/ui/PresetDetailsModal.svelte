<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { X, ShieldAlert, Check } from "lucide-svelte";
  import { fade, fly } from "svelte/transition";

  export let show = false;
  export let preset: {
    name: string;
    rule_pattern: string;
    rules: { id: string; name: string }[];
    severity: string;
  } | null = null;
  export let activeRules: string[] = [];

  const dispatch = createEventDispatcher<{
    close: void;
    toggleRule: { ruleId: string; enabled: boolean };
  }>();

  // Helper to check if a specific rule is active
  $: isRuleActive = (ruleId: string) => {
    if (!preset) return false;
    // If the wildcard is active, all rules under it are active
    if (activeRules.includes(preset.rule_pattern)) return true;
    // Otherwise, check if the specific rule ID is active
    return activeRules.includes(ruleId);
  };
</script>

{#if show && preset}
  <div
    class="fixed inset-0 z-[150] flex items-center justify-center bg-slate-950/80 backdrop-blur-sm"
    in:fade={{ duration: 200 }}
    out:fade={{ duration: 150 }}
  >
    <div
      class="bg-slate-900 border border-slate-700 w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]"
      in:fly={{ y: 20, duration: 300 }}
    >
      <!-- Header -->
      <div
        class="px-6 py-4 border-b border-slate-800 flex justify-between items-center bg-slate-950/50"
      >
        <div class="flex items-center gap-3">
          <div class="p-2 bg-blue-500/10 text-blue-400 rounded-lg">
            <ShieldAlert size={20} />
          </div>
          <div>
            <h3 class="text-lg font-bold text-slate-100 leading-tight">{preset.name}</h3>
            <p class="text-xs text-slate-500 font-mono">Pattern: {preset.rule_pattern}</p>
          </div>
        </div>
        <button
          on:click={() => dispatch("close")}
          class="text-slate-500 hover:text-slate-300 transition-colors p-1 rounded-md hover:bg-slate-800"
        >
          <X size={20} />
        </button>
      </div>

      <!-- Body (Scrollable) -->
      <div class="flex-1 overflow-y-auto p-6 space-y-4 no-scrollbar">
        <div
          class="bg-blue-500/10 border border-blue-500/20 text-blue-400 text-sm px-4 py-3 rounded-lg flex items-start gap-3"
        >
          <ShieldAlert size={18} class="shrink-0 mt-0.5" />
          <p>
            You can selectively disable individual signatures within this protection module.
            Disabling a signature will automatically convert the master wildcard (<span
              class="font-mono text-xs">{preset.rule_pattern}</span
            >) into individual rules in your active configuration.
          </p>
        </div>

        <div class="border border-slate-800 rounded-lg overflow-hidden bg-slate-950/30">
          <table class="w-full text-left text-sm">
            <thead
              class="bg-slate-900/80 border-b border-slate-800 text-slate-400 font-semibold text-xs uppercase tracking-wider"
            >
              <tr>
                <th class="px-4 py-3">Signature ID</th>
                <th class="px-4 py-3">Description</th>
                <th class="px-4 py-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/50">
              {#each preset.rules as rule}
                <tr class="hover:bg-slate-800/30 transition-colors">
                  <td class="px-4 py-3 font-mono text-blue-400 text-xs w-32">{rule.id}</td>
                  <td class="px-4 py-3 text-slate-300 font-medium">{rule.name}</td>
                  <td class="px-4 py-3 text-right">
                    <label class="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={isRuleActive(rule.id)}
                        on:change={(e) =>
                          dispatch("toggleRule", {
                            ruleId: rule.id,
                            enabled: e.currentTarget.checked,
                          })}
                        class="sr-only peer"
                      />
                      <div
                        class="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-500"
                      ></div>
                    </label>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Footer -->
      <div class="px-6 py-4 border-t border-slate-800 bg-slate-950/50 flex justify-end">
        <button
          on:click={() => dispatch("close")}
          class="px-6 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium rounded-lg transition-colors"
        >
          Done
        </button>
      </div>
    </div>
  </div>
{/if}
