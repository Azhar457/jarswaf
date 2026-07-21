<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import {
    Shield,
    Activity,
    Lock,
    Globe,
    Server,
    Menu,
    LayoutDashboard,
    ShieldCheck,
    Terminal,
  } from "lucide-svelte";
  import SidebarItem from "./SidebarItem.svelte";

  export let activeTab: string = "dashboard";
  export let isCollapsed: boolean = false;

  const dispatch = createEventDispatcher();

  const menuSections = [
    {
      title: "MAIN",
      items: [
        { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
        { id: "traffic", label: "Live Logs", icon: Terminal },
      ],
    },
    {
      title: "SECURITY",
      items: [
        { id: "threats", label: "Threat Intel", icon: Shield },
        { id: "rules", label: "WAF Rules", icon: Shield },
        { id: "rate_limits", label: "Rate Limiting", icon: Activity },
        { id: "access_control", label: "Access Control", icon: ShieldCheck },
      ],
    },
    {
      title: "CONFIG",
      items: [
        { id: "vhosts", label: "VHost Configuration", icon: Globe },
        { id: "ssl", label: "SSL Certificates", icon: Lock },
        { id: "nodes", label: "Agent Nodes", icon: Server },
      ],
    },
  ];

  function handleTabChange(id: string) {
    dispatch("tabChange", id);
  }
</script>

<aside
  class={`bg-bg-secondary border-r border-border-subtle flex flex-col transition-all duration-300 ${isCollapsed ? "w-16" : "w-64"} h-full`}
>
  <!-- Logo Area -->
  <div class="h-16 flex items-center justify-between px-4 border-b border-border-subtle">
    {#if !isCollapsed}
      <div class="flex items-center gap-2 text-text-primary font-bold text-lg tracking-wider">
        <Shield class="text-accent-blue" size={24} />
        <span>jarsWAF</span>
      </div>
    {/if}
    <button
      class="text-text-muted hover:text-text-primary p-1 rounded-md hover:bg-surface-hover/30"
      on:click={() => dispatch("toggleCollapse")}
    >
      <Menu size={20} />
    </button>
  </div>

  <!-- Navigation -->
  <div class="flex-1 overflow-y-auto no-scrollbar py-4">
    {#each menuSections as section}
      <div class="mb-6">
        {#if !isCollapsed}
          <div class="px-6 mb-2 text-xs font-semibold text-text-muted tracking-wider">
            {section.title}
          </div>
        {/if}
        <div class="space-y-0.5">
          {#each section.items as item}
            <SidebarItem
              icon={item.icon}
              label={item.label}
              active={activeTab === item.id}
              {isCollapsed}
              on:click={() => handleTabChange(item.id)}
            />
          {/each}
        </div>
      </div>
    {/each}
  </div>
</aside>
