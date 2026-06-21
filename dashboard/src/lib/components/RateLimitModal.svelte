<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let show = false;
  export let isEditing = false;
  export let name = "";
  export let limit = "";
  export let burst = 0;
  export let path = "/*";
  export let description = "";

  const dispatch = createEventDispatcher<{
    close: void;
    save: {
      name: string;
      limit: string;
      burst: number;
      path: string;
      description: string;
    };
  }>();

  function handleSave() {
    if (!name || !limit) return;
    dispatch('save', {
      name,
      limit,
      burst,
      path: path || "/*",
      description
    });
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
    <div class="glass-panel rounded-2xl w-full max-w-[500px] p-6 shadow-2xl flex flex-col gap-5 my-auto border border-outline-variant">
      <!-- Header -->
      <div class="flex justify-between items-center border-b border-outline-variant/30 pb-4">
        <h3 class="font-headline-md text-xl font-bold text-on-surface">
          {isEditing ? 'Edit Rate Policy' : 'Create Rate Policy'}
        </h3>
        <button 
          on:click={handleClose} 
          type="button"
          class="text-on-surface-variant/70 hover:text-primary transition-colors cursor-pointer bg-transparent border-none flex items-center justify-center p-1.5 rounded-full hover:bg-white/5"
        >
          <span class="material-symbols-outlined text-xl">close</span>
        </button>
      </div>

      <!-- Form Fields -->
      <div class="flex flex-col gap-4">
        <div class="flex flex-col gap-1.5">
          <label for="tier_name" class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">Tier Name</label>
          <input 
            id="tier_name"
            type="text" 
            placeholder="e.g. API Gateway Sync" 
            bind:value={name}
            class="bg-surface-container-low border border-outline-variant rounded-lg p-3 text-sm outline-none focus:border-primary text-on-surface transition-all focus:ring-1 focus:ring-primary/20"
          />
        </div>

        <div class="flex flex-col gap-1.5">
          <label for="path_pattern" class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">Target URL Path Pattern</label>
          <input 
            id="path_pattern"
            type="text" 
            placeholder="e.g. /api/* or /login" 
            bind:value={path}
            class="bg-surface-container-low border border-outline-variant rounded-lg p-3 text-sm outline-none focus:border-primary text-on-surface font-mono transition-all focus:ring-1 focus:ring-primary/20"
          />
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label for="limit" class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">Rate Limit String</label>
            <input 
              id="limit"
              type="text" 
              placeholder="e.g. 200 requests/minute" 
              bind:value={limit}
              class="bg-surface-container-low border border-outline-variant rounded-lg p-3 text-sm outline-none focus:border-primary text-on-surface transition-all focus:ring-1 focus:ring-primary/20"
            />
          </div>

          <div class="flex flex-col gap-1.5">
            <label for="burst" class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">Burst Token Capacity</label>
            <input 
              id="burst"
              type="number" 
              placeholder="e.g. 50" 
              bind:value={burst}
              class="bg-surface-container-low border border-outline-variant rounded-lg p-3 text-sm outline-none focus:border-primary text-on-surface font-mono transition-all focus:ring-1 focus:ring-primary/20"
            />
          </div>
        </div>

        <div class="flex flex-col gap-1.5">
          <label for="description" class="text-[11px] font-bold text-on-surface-variant uppercase tracking-wider">Policy Description</label>
          <textarea 
            id="description" 
            placeholder="Describe what this rate limiting tier is enforced for..." 
            bind:value={description}
            class="bg-surface-container-low border border-outline-variant rounded-lg p-3 text-sm outline-none focus:border-primary text-on-surface h-24 resize-none transition-all focus:ring-1 focus:ring-primary/20"
          ></textarea>
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
          {isEditing ? 'Save Changes' : 'Create Policy'}
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
