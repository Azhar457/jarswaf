<script lang="ts">
  import Sidebar from "./Sidebar.svelte";
  import Topbar from "./Topbar.svelte";

  export let activeTab: string = "dashboard";
  let isSidebarCollapsed = false;

  function handleTabChange(event: CustomEvent<string>) {
    activeTab = event.detail;
  }
</script>

<div class="h-screen w-screen bg-slate-950 text-slate-100 flex overflow-hidden font-sans">
  <Sidebar
    {activeTab}
    isCollapsed={isSidebarCollapsed}
    on:tabChange={handleTabChange}
    on:toggleCollapse={() => (isSidebarCollapsed = !isSidebarCollapsed)}
  />

  <div class="flex-1 flex flex-col min-w-0 overflow-hidden">
    <Topbar systemStatus="online" on:deploy />

    <main class="flex-1 overflow-y-auto bg-slate-950 p-6 md:p-8">
      <div class="max-w-7xl mx-auto">
        <slot />
      </div>
    </main>
  </div>
</div>
