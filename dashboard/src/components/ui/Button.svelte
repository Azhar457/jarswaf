<script lang="ts">
  export let variant: "primary" | "secondary" | "danger" | "ghost" = "primary";
  export let type: "button" | "submit" | "reset" = "button";
  export let disabled: boolean = false;
  export let className: string = "";
  export let title: string | undefined = undefined;

  const variantStyles = {
    primary: "bg-accent-blue hover:bg-accent-blue-hover active:bg-blue-700 text-white shadow-lg shadow-accent-blue-glow focus:ring-accent-blue/50",
    secondary: "bg-slate-800 hover:bg-surface-hover active:bg-surface-card text-slate-200 border border-border-default focus:ring-slate-500/50",
    danger: "bg-error hover:bg-red-500 active:bg-red-700 text-white shadow-lg shadow-glow-error focus:ring-error/50",
    ghost: "bg-transparent hover:bg-surface-hover/30 active:bg-surface-hover text-text-secondary focus:ring-slate-500/50",
  };
</script>

<button
  {type}
  {disabled}
  {title}
  class={`inline-flex items-center justify-center font-semibold px-4 py-2.5 rounded-xl transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-950 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer text-sm border-none ${variantStyles[variant]} ${className}`}
  on:click
>
  <slot />
</button>
