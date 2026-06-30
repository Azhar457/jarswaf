<script lang="ts">
  export let variant: "success" | "danger" | "warning" | "neutral" | "primary" | "info" = "neutral";
  export let className: string = "";

  const variantStyles = {
    success: "bg-success-bg text-success border border-success/15",
    danger: "bg-error-bg text-error border border-error/15",
    warning: "bg-warning-bg text-warning border border-warning/15",
    primary: "bg-accent-blue/10 text-accent-blue border border-accent-blue/15",
    info: "bg-info-bg text-info border border-info/15",
    neutral: "bg-slate-800 text-slate-300 border border-slate-700",
  };
</script>

<span
  class={`inline-flex items-center px-3 py-0.5 rounded-full text-xs font-semibold ${variantStyles[variant]} ${className}`}
>
  <slot />
</span>
