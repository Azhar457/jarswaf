<script lang="ts">
  import Sidebar from "./Sidebar.svelte";
  import Topbar from "./Topbar.svelte";

  export let activeTab: string = "dashboard";
  let isSidebarCollapsed = false;
  let isMobileSidebarOpen = false;

  function handleTabChange(event: CustomEvent<string>) {
    activeTab = event.detail;
    isMobileSidebarOpen = false; // Auto-close drawer on mobile tab selection
  }
</script>

<div class="h-screen w-screen bg-bg-primary text-text-primary flex overflow-hidden font-sans relative">
  <!-- Desktop Sidebar (Permanen di Desktop) -->
  <div class="hidden lg:flex h-full shrink-0">
    <Sidebar
      {activeTab}
      isCollapsed={isSidebarCollapsed}
      on:tabChange={handleTabChange}
      on:toggleCollapse={() => (isSidebarCollapsed = !isSidebarCollapsed)}
    />
  </div>

  <!-- Mobile Sidebar Overlay Backdrop -->
  {#if isMobileSidebarOpen}
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div
      class="fixed inset-0 bg-black/60 backdrop-blur-xs z-40 lg:hidden"
      on:click={() => (isMobileSidebarOpen = false)}
    ></div>
  {/if}

  <!-- Mobile Sidebar Drawer (Slide-out dari kiri) -->
  <div
    class={`fixed inset-y-0 left-0 z-50 w-64 bg-bg-secondary border-r border-border-subtle transform transition-transform duration-300 ease-in-out lg:hidden ${
      isMobileSidebarOpen ? "translate-x-0" : "-translate-x-full"
    }`}
  >
    <Sidebar
      {activeTab}
      isCollapsed={false}
      on:tabChange={handleTabChange}
      on:toggleCollapse={() => (isMobileSidebarOpen = false)}
    />
  </div>

  <!-- Main Container -->
  <div class="flex-1 flex flex-col min-w-0 overflow-hidden">
    <Topbar
      systemStatus="online"
      on:deploy
      on:toggleMobileSidebar={() => (isMobileSidebarOpen = !isMobileSidebarOpen)}
    />

    <main
      class={`flex-1 bg-bg-primary p-4 md:p-8 ${activeTab === "traffic" ? "flex flex-col overflow-hidden min-h-0" : "overflow-y-auto"}`}
    >
      <div
        class={`max-w-[1600px] mx-auto w-full ${activeTab === "traffic" ? "flex-1 flex flex-col overflow-hidden min-h-0" : ""}`}
      >
        <slot />
      </div>
    </main>
  </div>
</div>
