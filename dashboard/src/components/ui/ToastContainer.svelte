<script lang="ts">
  import { toast } from '../../lib/toast';
  import { CheckCircle2, AlertCircle, Info, AlertTriangle, X } from 'lucide-svelte';
  import { fly, fade } from 'svelte/transition';
</script>

<div class="fixed top-24 right-8 z-[100] flex flex-col gap-3 pointer-events-none">
  {#each $toast as t (t.id)}
    <div
      in:fly={{ x: 50, duration: 300 }}
      out:fade={{ duration: 200 }}
      class="pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-lg shadow-xl border backdrop-blur-md min-w-[300px]
        {t.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
         t.type === 'error' ? 'bg-red-500/10 border-red-500/30 text-red-400' :
         t.type === 'warning' ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
         'bg-blue-500/10 border-blue-500/30 text-blue-400'}"
    >
      <div class="shrink-0">
        {#if t.type === 'success'}
          <CheckCircle2 size={20} />
        {:else if t.type === 'error'}
          <AlertCircle size={20} />
        {:else if t.type === 'warning'}
          <AlertTriangle size={20} />
        {:else}
          <Info size={20} />
        {/if}
      </div>
      <p class="flex-1 font-medium text-sm text-slate-200">{t.message}</p>
      <button class="shrink-0 opacity-50 hover:opacity-100 transition-opacity" on:click={() => toast.remove(t.id)}>
        <X size={16} />
      </button>
    </div>
  {/each}
</div>
