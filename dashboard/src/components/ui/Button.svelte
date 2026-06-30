<script lang="ts">
  export let variant: "primary" | "secondary" | "danger" | "ghost" = "primary";
  export let type: "button" | "submit" | "reset" = "button";
  export let disabled: boolean = false;
  export let className: string = "";
  export let title: string | undefined = undefined;

  const variantStyles = {
    primary: "bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white shadow-lg shadow-blue-950/20 focus:ring-blue-500/50",
    secondary: "bg-slate-800 hover:bg-slate-700 active:bg-slate-900 text-slate-200 border border-slate-700/80 focus:ring-slate-500/50",
    danger: "bg-red-600 hover:bg-red-500 active:bg-red-700 text-white shadow-lg shadow-red-950/20 focus:ring-red-500/50",
    ghost: "bg-transparent hover:bg-slate-800/50 active:bg-slate-800 text-slate-300 focus:ring-slate-500/50",
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
