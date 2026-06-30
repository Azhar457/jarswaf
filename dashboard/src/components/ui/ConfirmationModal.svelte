<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { AlertTriangle } from "lucide-svelte";
  import { fade, fly } from "svelte/transition";
  import Button from "./Button.svelte";

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
    class="fixed inset-0 z-200 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm"
    in:fade={{ duration: 200 }}
    out:fade={{ duration: 150 }}
  >
    <div
      class="bg-bg-secondary border border-border-muted w-full max-w-md rounded-2xl shadow-premium overflow-hidden"
      in:fly={{ y: 20, duration: 300 }}
    >
      <div class="p-6">
        <div class="flex items-start gap-4">
          <div class="p-3 bg-error-bg text-error rounded-full shrink-0 border border-error/10">
            <AlertTriangle size={24} />
          </div>
          <div class="flex-1">
            <h3 class="text-lg font-bold text-white mb-2">{title}</h3>
            <p class="text-text-secondary text-sm leading-relaxed">{message}</p>
          </div>
        </div>
      </div>
      <div class="bg-slate-900/20 px-6 py-4 border-t border-border-muted flex justify-end gap-3">
        <Button
          variant="ghost"
          on:click={onCancel}
        >
          {cancelText}
        </Button>
        <Button
          variant="danger"
          on:click={onConfirm}
        >
          {confirmText}
        </Button>
      </div>
    </div>
  </div>
{/if}
