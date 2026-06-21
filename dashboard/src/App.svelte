<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import Layout from './components/layout/Layout.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import VHostConfig from './pages/VHostConfig.svelte';
  import RateLimiting from './pages/RateLimiting.svelte';
  import LiveLogs from './pages/LiveLogs.svelte';
  import RuleEngine from './pages/RuleEngine.svelte';
  import ThreatIntel from './pages/ThreatIntel.svelte';
  import SSLCertificates from './pages/SSLCertificates.svelte';
  import AgentNodes from './pages/AgentNodes.svelte';
  
  import AlertBanner from './lib/components/AlertBanner.svelte';
  import ToastContainer from './components/ui/ToastContainer.svelte';
  import DeployToast from './lib/components/DeployToast.svelte';
  import { initGlobalStore, cleanupGlobalStore, latestLog } from './lib/stores';

  const controllerUrl = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8080';
  let activeTab = 'dashboard';

  let showDeployToast = false;
  let dismissedAlert = false;
  let activeAlert: any = null;

  $: if ($latestLog) {
    if ($latestLog.action.toLowerCase() === 'block' || $latestLog.action.toLowerCase() === 'ratelimit') {
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

<Layout bind:activeTab on:deploy={deployRules}>
  {#if activeTab === 'dashboard'}
    <Dashboard />
  {:else if activeTab === 'threats'}
    <ThreatIntel />
  {:else if activeTab === 'rules'}
    <RuleEngine />
  {:else if activeTab === 'rate_limits'}
    <RateLimiting />
  {:else if activeTab === 'vhosts'}
    <VHostConfig />
  {:else if activeTab === 'ssl'}
    <SSLCertificates />
  {:else if activeTab === 'nodes'}
    <AgentNodes />
  {:else if activeTab === 'traffic'}
    <LiveLogs />
  {/if}
</Layout>

<DeployToast show={showDeployToast} />
<ToastContainer />

<AlertBanner
  show={activeAlert != null && !dismissedAlert}
  alert={activeAlert}
  on:dismiss={() => dismissedAlert = true}
/>
