<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { AlertTriangle, X } from "lucide-svelte";
  import { fade, fly } from "svelte/transition";

  export let show = false;
  export let title = "Confirm Action";
  export let message = "Are you sure you want to perform this action? This cannot be undone.";
  export let confirmText = "Delete";
  export let cancelText = "Cancel";

  const dispatch = createEventDispatcher<{
    confirm: void;
    cancel: void;
  }>();

  function onConfirm() {
    dispatch("confirm");
  }

  function onCancel() {
    dispatch("cancel");
  }
</script>

{#if show}
  <div
    class="fixed inset-0 z-200 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm"
    in:fade={{ duration: 200 }}
    out:fade={{ duration: 150 }}
  >
    <div
      class="bg-slate-900 border border-slate-700 w-full max-w-md rounded-xl shadow-2xl overflow-hidden"
      in:fly={{ y: 20, duration: 300 }}
    >
      <div class="p-6">
        <div class="flex items-start gap-4">
          <div class="p-3 bg-red-500/10 text-red-400 rounded-full shrink-0">
            <AlertTriangle size={24} />
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-slate-100 mb-2">{title}</h3>
            <p class="text-slate-400 text-sm leading-relaxed">{message}</p>
          </div>
        </div>
      </div>
      <div class="bg-slate-950/50 px-6 py-4 border-t border-slate-800 flex justify-end gap-3">
        <button
          on:click={onCancel}
          class="px-4 py-2 text-sm font-medium text-slate-300 hover:bg-slate-800 rounded-lg transition-colors"
        >
          {cancelText}
        </button>
        <button
          on:click={onConfirm}
          class="px-4 py-2 text-sm font-bold bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors shadow-lg shadow-red-500/20"
        >
          {confirmText}
        </button>
      </div>
    </div>
  </div>
{/if}
