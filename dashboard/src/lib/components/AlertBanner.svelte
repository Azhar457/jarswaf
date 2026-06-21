<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let show: boolean = false;

  interface AlertType {
    client_ip: string;
    method: string;
    path: string;
    reason: string;
    action: string;
  }

  export let alert: Partial<AlertType> = {};

  const dispatch = createEventDispatcher<{
    dismiss: void;
  }>();
</script>

{#if show && alert}
  <div class="fixed bottom-0 left-0 w-full bg-error text-on-error px-8 py-4 flex justify-between items-center z-[100] border-t border-error-container shadow-2xl transition-all">
    <div class="flex items-center gap-4 font-code-md text-xs tracking-tighter uppercase font-mono overflow-hidden whitespace-nowrap text-ellipsis mr-8">
      <span class="font-black text-xs text-red-500">▲ CRITICAL ALERT:</span>
      <span class="font-bold">NG ORIGIN {alert.client_ip}</span>
      <span>•</span>
      <span>PROTOCOL VIOLATION ON {alert.method} {alert.path}</span>
      <span>•</span>
      <span>{alert.reason}</span>
      <span>•</span>
      <span class="font-black">BLOCKING ORIGIN</span>
    </div>
    <button
      type="button"
      class="px-4 py-2 bg-on-error text-error font-bold rounded text-xs transition-colors cursor-pointer border-none hover:opacity-90 whitespace-nowrap"
      on:click={() => dispatch('dismiss')}
    >
      DISMISS
    </button>
  </div>
{/if}
