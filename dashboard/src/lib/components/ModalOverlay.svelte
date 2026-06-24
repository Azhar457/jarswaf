<script>
  import { createEventDispatcher } from "svelte";

  /** @type {boolean} */
  export let show = false;
  /** @type {string} */
  export let title = "";
  /** @type {string} */
  export let maxWidth = "max-w-2xl";

  const dispatch = createEventDispatcher();

  /** @param {MouseEvent} e */
  function handleBackdropClick(e) {
    if (e.target === e.currentTarget) {
      dispatch("close");
    }
  }
</script>

{#if show}
  <!-- svelte-ignore a11y-click-events-have-key-events -->
  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <div
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-8 overflow-y-auto"
    on:click={handleBackdropClick}
  >
    <div
      class="glass-panel rounded-xl {maxWidth} w-full p-8 shadow-2xl flex flex-col gap-4 my-auto border border-outline-variant"
    >
      <!-- Header -->
      <div class="flex justify-between items-center border-b border-outline-variant pb-6">
        <h3 class="font-headline-md text-headline-md text-on-surface">{title}</h3>
        <button
          on:click={() => dispatch("close")}
          class="text-outline hover:text-primary transition-colors cursor-pointer bg-transparent border-none"
        >
          <span class="material-symbols-outlined">close</span>
        </button>
      </div>

      <!-- Body -->
      <slot />

      <!-- Footer -->
      <div class="flex justify-end gap-4 border-t border-outline-variant pt-6 mt-4">
        <slot name="footer" />
      </div>
    </div>
  </div>
{/if}
