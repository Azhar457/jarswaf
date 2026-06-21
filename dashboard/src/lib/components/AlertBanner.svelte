<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { AlertOctagon } from 'lucide-svelte';

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
  <div class="fixed top-4 left-1/2 -translate-x-1/2 w-full max-w-lg z-100 transition-all duration-500 {show ? 'opacity-100 translate-y-0' : 'opacity-0 -translate-y-10 pointer-events-none'}" role="alert">
    <div class="bg-red-500/10 border border-red-500/30 rounded-xl p-4 shadow-2xl backdrop-blur-md flex items-start gap-4">
      <div class="text-red-400 mt-1 shrink-0">
        <AlertOctagon size={24} />
      </div>
      <div class="flex-1">
        <h3 class="text-red-400 font-bold tracking-wide text-sm mb-1">{alert?.reason || 'CRITICAL SECURITY EVENT DETECTED'}</h3>
        <div class="text-slate-300 text-sm space-y-1">
          <p><span class="text-slate-500">Source:</span> <span class="font-mono text-red-300 font-medium">{alert?.client_ip}</span></p>
          <p><span class="text-slate-500">Target:</span> <span class="font-mono text-slate-200">{alert?.method} {alert?.path}</span></p>
          <p><span class="text-slate-500">Action Taken:</span> <span class="font-bold text-red-400">{alert?.action}</span></p>
        </div>
      </div>
      <button
        type="button"
        class="text-slate-400 hover:text-white transition-colors"
        on:click={() => dispatch('dismiss')}
      >
        ✕
      </button>
    </div>
  </div>
{/if}
