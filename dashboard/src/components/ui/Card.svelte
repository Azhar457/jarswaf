<script lang="ts">
  export let className: string = "";
</script>

<div class={`bg-slate-800 border border-slate-700/800 rounded-xl p-4 shadow-lg ${className}`}>
  <slot />
</div>
