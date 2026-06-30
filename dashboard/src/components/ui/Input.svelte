<script lang="ts">
  export let label: string = "";
  export let id: string = "";
  export let type: string = "text";
  export let placeholder: string = "";
  export let value: string = "";
  export let error: string = "";
  export let required: boolean = false;
  export let disabled: boolean = false;
  export let readonly: boolean = false;
  export let className: string = "";
</script>

<div class={`space-y-1.5 w-full ${className}`}>
  {#if label}
    <label for={id} class="block text-xs font-semibold text-text-secondary uppercase tracking-wider">
      {label}
      {#if required}<span class="text-red-500 ml-0.5">*</span>{/if}
    </label>
  {/if}
  <input
    {id}
    {type}
    {placeholder}
    {required}
    {disabled}
    {readonly}
    bind:value
    class={`input-field ${error ? 'border-red-500/50 focus:ring-red-500/50 focus:border-red-500' : ''} ${disabled ? 'opacity-50 cursor-not-allowed bg-slate-900/30' : ''}`}
    on:input
    on:change
    on:keydown
  />
  {#if error}
    <p class="text-red-400 text-xs font-medium mt-1 flex items-center gap-1.5">
      <span class="inline-block w-1.5 h-1.5 bg-red-500 rounded-full"></span>
      {error}
    </p>
  {/if}
</div>
