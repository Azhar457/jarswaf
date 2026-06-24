<script lang="ts">
  import Card from "./Card.svelte";

  export let title: string;
  export let value: string | number;
  export let iconColor: string = "text-blue-500";
  export let className: string = "";
</script>

<Card className={`flex items-center p-6 ${className}`}>
  <div class="flex-1">
    <h3 class="text-slate-400 text-sm font-medium tracking-wider uppercase mb-1">{title}</h3>
    <div class="text-3xl font-bold text-slate-100">{value}</div>
  </div>
  <div class={`p-3 rounded-lg bg-slate-900/50 ${iconColor}`}>
    <slot name="icon" />
  </div>
</Card>
