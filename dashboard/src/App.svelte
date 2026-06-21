<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import Overview from './lib/Overview.svelte';
  import LiveLogs from './lib/LiveLogs.svelte';
  import VirtualHosts from './lib/VirtualHosts.svelte';
  import RuleEngine from './lib/RuleEngine.svelte';
  import RateLimiting from './lib/RateLimiting.svelte';
  import Sidebar from './lib/components/Sidebar.svelte';
  import TopBar from './lib/components/TopBar.svelte';
  import AlertBanner from './lib/components/AlertBanner.svelte';
  import DeployToast from './lib/components/DeployToast.svelte';
  import { initGlobalStore, cleanupGlobalStore, connectionStatus, stats, latestLog } from './lib/stores';

  const controllerUrl = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8080';
  let activeTab = 'overview';
  let isSidebarCollapsed = false;

  let showDeployToast = false;
  let dismissedAlert = false;
  let activeAlert: any = {
    client_ip: '192.168.1.104',
    method: 'GET',
    path: '/auth/admin',
    reason: 'SQLI PATTERN DETECTED IN USER-AGENT HEADER',
    action: 'BLOCK'
  };

  $: if ($latestLog) {
    if ($latestLog.action === 'Block' || $latestLog.action === 'block' || $latestLog.action === 'RateLimit' || $latestLog.action === 'ratelimit') {
      activeAlert = {
        client_ip: $latestLog.client_ip,
        method: $latestLog.method,
        path: $latestLog.path,
        reason: $latestLog.reason || 'ATTACK PATTERN DETECTED',
        action: $latestLog.action.toUpperCase()
      };
      dismissedAlert = false;
    }
  }

  onMount(() => {
    initGlobalStore(controllerUrl);
  });

  function deployRules() {
    showDeployToast = true;
    setTimeout(() => {
      showDeployToast = false;
    }, 3000);
  }

  onDestroy(() => {
    cleanupGlobalStore();
  });
</script>

<div class="min-h-screen bg-surface-container-lowest text-on-surface font-body-sm flex">
  <!-- Sidebar Component -->
  <Sidebar
    {activeTab}
    isCollapsed={isSidebarCollapsed}
    on:tabChange={(e) => activeTab = e.detail}
    on:toggleCollapse={() => isSidebarCollapsed = !isSidebarCollapsed}
    on:deployRules={deployRules}
  />

  <!-- Main Content Area -->
  <div 
    class="flex-1 transition-all duration-300 flex flex-col min-h-screen"
    style="margin-left: {isSidebarCollapsed ? '64px' : '256px'};"
  >
    <!-- Top App Bar -->
    <TopBar
      blockedCount={$stats.blocked}
      isOnline={$connectionStatus === 'online'}
    />

    <!-- Page Content -->
    <main class="p-8 flex-1 overflow-y-auto bg-background" style="padding-bottom: {activeAlert && !dismissedAlert ? '80px' : '32px'};">
      {#if activeTab === 'overview'}
        <Overview {controllerUrl} />
      {/if}
      {#if activeTab === 'logs'}
        <LiveLogs {controllerUrl} />
      {/if}
      {#if activeTab === 'vhosts'}
        <VirtualHosts {controllerUrl} />
      {/if}
      {#if activeTab === 'rules'}
        <RuleEngine {controllerUrl} />
      {/if}
      {#if activeTab === 'rate_limits'}
        <RateLimiting {controllerUrl} />
      {/if}
    </main>
  </div>
</div>

<!-- Deploy Toast -->
<DeployToast show={showDeployToast} />

<!-- Bottom Critical Alert Banner -->
<AlertBanner
  show={activeAlert != null && !dismissedAlert}
  alert={activeAlert}
  on:dismiss={() => dismissedAlert = true}
/>
