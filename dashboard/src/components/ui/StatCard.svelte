<script lang="ts">
  import Card from "./Card.svelte";

  export let title: string;
  export let value: string | number;
  export let iconColor: string = "text-blue-500";
  export let className: string = "";
</script>

<Card className={`flex items-center p-6 ${className}`} interactive={true}>
  <div class="flex-1">
    <h3 class="text-xs font-bold text-text-secondary uppercase tracking-wider mb-2">{title}</h3>
    <div class="text-3xl font-extrabold text-text-primary tracking-tight">{value}</div>
  </div>
  <div class={`p-4 rounded-2xl bg-slate-950/40 border border-border-muted/60 ${iconColor} shadow-inner`}>
    <slot name="icon" />
  </div>
</Card>
