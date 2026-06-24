<script lang="ts">
  export let variant: "success" | "danger" | "warning" | "neutral" | "primary" = "neutral";
  export let className: string = "";

  const variantStyles = {
    success: "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20",
    danger: "bg-red-500/10 text-red-500 border border-red-500/20",
    warning: "bg-amber-500/10 text-amber-500 border border-amber-500/20",
    primary: "bg-blue-600/10 text-blue-500 border border-blue-600/20",
    neutral: "bg-slate-700 text-slate-300 border border-slate-600",
  };
</script>

<span
  class={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${variantStyles[variant]} ${className}`}
>
  <slot />
</span>
