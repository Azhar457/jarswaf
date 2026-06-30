<script lang="ts">
  import { createEventDispatcher } from "svelte";

  export let activeTab: string = "overview";
  export let isCollapsed: boolean = false;

  const dispatch = createEventDispatcher<{
    tabChange: string;
    toggleCollapse: void;
    deployRules: void;
  }>();

  const navItems = [
    { id: "overview", label: "Dashboard", icon: "dashboard" },
    { id: "logs", label: "Threat Intel", icon: "security" },
    { id: "vhosts", label: "Traffic Analysis", icon: "analytics" },
    { id: "rules", label: "Firewall Rules", icon: "security_update_good" },
    { id: "rate_limits", label: "Settings", icon: "settings" },
  ];

  function handleTabChange(tabId: string) {
    dispatch("tabChange", tabId);
  }

  function handleToggleCollapse() {
    dispatch("toggleCollapse");
  }

  function handleDeployRules() {
    dispatch("deployRules");
  }
</script>

<aside
  class="h-screen sticky top-0 z-50 bg-surface-container-lowest border-r border-outline-variant transition-all duration-300 flex flex-col py-6 shrink-0"
  style="width: {isCollapsed ? '64px' : '256px'};"
>
  <!-- Logo Section -->
  <div class="mb-8 flex items-center justify-between px-4">
    {#if !isCollapsed}
      <div class="flex items-center">
        <span class="material-symbols-outlined text-primary" style="font-size: 32px;">security</span
        >
        <div class="flex flex-col">
          <span class="font-headline-md text-headline-md text-on-surface font-bold leading-tight"
            >jarsWAF</span
          >
          <span class="font-code-md text-body-sm text-on-surface-variant leading-tight"
            >v2.4.0-prod</span
          >
        </div>
      </div>
    {:else}
      <span class="material-symbols-outlined text-primary mx-auto" style="font-size: 32px;"
        >security</span
      >
    {/if}
  </div>

  <!-- Toggle Button -->
  <div class="px-4 mb-4">
    <button
      on:click={handleToggleCollapse}
      class="w-full flex items-center justify-center p-2 rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors"
      title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
    >
      <span class="material-symbols-outlined">
        {isCollapsed ? "menu" : "menu_open"}
      </span>
    </button>
  </div>

  <!-- Navigation Items -->
  <nav class="flex flex-col flex-1 px-2">
    {#each navItems as item (item.id)}
      <button
        on:click={() => handleTabChange(item.id)}
        class="flex items-center p-4 rounded-lg transition-colors relative w-full text-left
          {activeTab === item.id
          ? 'text-primary font-bold bg-primary-container/10 border-r-2 border-primary'
          : 'text-on-surface-variant hover:bg-surface-container-high'}"
        title={isCollapsed ? item.label : ""}
      >
        <span
          class="material-symbols-outlined shrink-0"
          style={activeTab === item.id ? "font-variation-settings: 'FILL' 1;" : ""}
        >
          {item.icon}
        </span>
        {#if !isCollapsed}
          <span class="whitespace-nowrap overflow-hidden text-body-sm font-body-sm">
            {item.label}
          </span>
        {/if}
      </button>
    {/each}
  </nav>

  <!-- Bottom Section -->
  <div class="border-t border-outline-variant pt-6 px-2 flex flex-col">
    <!-- Deploy Rules Button -->
    <button
      on:click={handleDeployRules}
      class="flex items-center justify-center p-4 rounded-lg bg-primary text-on-primary font-bold transition-colors hover:opacity-90 w-full"
      title={isCollapsed ? "Deploy Rules" : ""}
    >
      <span class="material-symbols-outlined shrink-0">rocket_launch</span>
      {#if !isCollapsed}
        <span class="whitespace-nowrap text-body-sm font-body-sm">Deploy Rules</span>
      {/if}
    </button>

    <!-- Footer Links -->
    {#if !isCollapsed}
      <div class="flex flex-col px-2 pt-2">
        <a
          href="https://github.com/Azhar457/jarswaf#readme"
          target="_blank"
          rel="noopener noreferrer"
          class="flex items-center text-on-surface-variant hover:text-on-surface text-body-sm font-body-sm transition-colors"
        >
          <span class="material-symbols-outlined" style="font-size: 16px;">description</span>
          Documentation
        </a>
        <a
          href="https://azhar457.github.io/note/"
          target="_blank"
          rel="noopener noreferrer"
          class="flex items-center text-on-surface-variant hover:text-on-surface text-body-sm font-body-sm transition-colors"
        >
          <span class="material-symbols-outlined" style="font-size: 16px;">support</span>
          Support
        </a>
      </div>
    {:else}
      <div class="flex flex-col items-center pt-2">
        <a
          href="https://github.com/Azhar457/jarswaf#readme"
          target="_blank"
          rel="noopener noreferrer"
          class="text-on-surface-variant hover:text-on-surface transition-colors"
          title="Documentation"
        >
          <span class="material-symbols-outlined" style="font-size: 16px;">description</span>
        </a>
        <a
          href="https://azhar457.github.io/note/"
          target="_blank"
          rel="noopener noreferrer"
          class="text-on-surface-variant hover:text-on-surface transition-colors"
          title="Support"
        >
          <span class="material-symbols-outlined" style="font-size: 16px;">support</span>
        </a>
      </div>
    {/if}
  </div>
</aside>
