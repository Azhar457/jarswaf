<script lang="ts">
  export let className: string = "";
  export let interactive: boolean = false;
</script>

<div class={`${interactive ? 'glass-panel-interactive' : 'glass-panel'} rounded-2xl p-6 ${className}`}>
  <slot />
</div>
