<script>
  /** @type {boolean} */
  export let show = false;

  /** @type {string} */
  export let message = "Rules successfully deployed to WAF nodes!";
</script>

{#if show}
  <div
    class="fixed top-24 right-8 bg-surface-container border border-primary/30 text-primary px-6 py-4 rounded shadow-xl flex items-center gap-4 z-50 animate-bounce"
  >
    <span
      class="material-symbols-outlined text-primary text-[20px]"
      style="font-variation-settings: 'FILL' 1;">check_circle</span
    >
    <span class="font-body-sm text-sm font-bold">{message}</span>
  </div>
{/if}
