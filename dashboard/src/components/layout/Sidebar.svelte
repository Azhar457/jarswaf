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
        { id: "traffic", label: "Traffic Analysis", icon: Activity },
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
  class={`bg-slate-900 border-r border-slate-800 flex flex-col transition-all duration-300 ${isCollapsed ? "w-16" : "w-64"} h-full`}
>
  <!-- Logo Area -->
  <div class="h-16 flex items-center justify-between px-4 border-b border-slate-800">
    {#if !isCollapsed}
      <div class="flex items-center gap-2 text-slate-100 font-bold text-lg tracking-wider">
        <Shield class="text-blue-500" size={24} />
        <span>AEGIS WAF</span>
      </div>
    {/if}
    <button
      class="text-slate-400 hover:text-slate-100 p-1 rounded-md hover:bg-slate-800"
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
          <div class="px-5 mb-2 text-xs font-semibold text-slate-500 tracking-wider">
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
