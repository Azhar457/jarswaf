<script lang="ts">
  /** Number of attacks prevented, displayed formatted in the pill */
  export let blockedCount: number = 0;
  /** Whether the system is currently online */
  export let isOnline: boolean = true;

  function formatCount(num: number): string {
    if (num < 1000) return num.toString();
    if (num < 1000000) {
      return (num / 1000).toFixed(1).replace('.0', '') + 'k';
    }
    return (num / 1000000).toFixed(1).replace('.0', '') + 'M';
  }
</script>

<header class="flex justify-between items-center h-20 px-8 bg-surface/80 backdrop-blur-md sticky top-0 z-40 border-b border-outline-variant">
  <!-- Left: Search -->
  <div class="flex items-center gap-6">
    <div class="relative w-72">
      <span class="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-[18px]">search</span>
      <input
        class="w-full bg-surface-container-lowest border-outline-variant border rounded py-2 pl-10 pr-4 text-body-sm font-body-sm text-on-surface placeholder:text-on-surface-variant focus:ring-1 focus:ring-primary focus:outline-none"
        placeholder="Search rules..."
        type="text"
      />
    </div>
  </div>

  <!-- Right: Pills + Actions -->
  <div class="flex items-center gap-4">
    <!-- Attacks Prevented Pill -->
    <span class="text-xs px-4 py-2 bg-surface-container rounded border border-outline-variant text-on-surface-variant hidden sm:inline-block">
      Attacks Prevented: <strong class="text-error">{formatCount(blockedCount)}</strong>
    </span>

    <!-- System Status Pill -->
    <div class="flex items-center gap-2 px-4 py-2 bg-primary-container/10 border border-primary/20 rounded">
      <div class="w-2 h-2 rounded-full {isOnline ? 'bg-primary animate-pulse' : 'bg-error'}"></div>
      <span class="text-[11px] font-bold text-primary uppercase tracking-tighter">
        {isOnline ? 'System Online' : 'System Offline'}
      </span>
    </div>

    <!-- Divider + Action Icons -->
    <div class="flex gap-2 border-l border-outline-variant pl-4 text-on-surface-variant items-center">
      <button type="button" class="p-2 hover:text-primary transition-colors cursor-pointer">
        <span class="material-symbols-outlined text-[20px]">notifications</span>
      </button>
      <button type="button" class="p-2 hover:text-primary transition-colors cursor-pointer">
        <span class="material-symbols-outlined text-[20px]">terminal</span>
      </button>
      <button type="button" class="p-2 hover:text-primary transition-colors cursor-pointer flex items-center">
        <span class="material-symbols-outlined text-[24px]">account_circle</span>
      </button>
    </div>
  </div>
</header>
