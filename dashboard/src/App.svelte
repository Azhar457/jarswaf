<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import Layout from "./components/layout/Layout.svelte";
  import Dashboard from "./pages/Dashboard.svelte";
  import VHostConfig from "./pages/VHostConfig.svelte";
  import RateLimiting from "./pages/RateLimiting.svelte";
  import LiveLogs from "./pages/LiveLogs.svelte";
  import RuleEngine from "./pages/RuleEngine.svelte";
  import ThreatIntel from "./pages/ThreatIntel.svelte";
  import SSLCertificates from "./pages/SSLCertificates.svelte";
  import AgentNodes from "./pages/AgentNodes.svelte";
  import AccessControl from "./pages/AccessControl.svelte";

  import AlertBanner from "./lib/components/AlertBanner.svelte";
  import ToastContainer from "./components/ui/ToastContainer.svelte";
  import DeployToast from "./lib/components/DeployToast.svelte";
  import { initGlobalStore, cleanupGlobalStore, latestLog, token } from "./lib/stores";
  import { toast } from "./lib/toast";
  import { Lock, Shield, Server, ArrowRight } from "lucide-svelte";

  const controllerUrl =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:8080";
  let activeTab = typeof window !== "undefined" ? localStorage.getItem("aegis_active_tab") || "dashboard" : "dashboard";
  $: if (typeof window !== "undefined") {
    localStorage.setItem("aegis_active_tab", activeTab);
  }

  let showDeployToast = false;
  let dismissedAlert = false;
  let activeAlert: any = null;

  let needsLogin = false;
  let isCheckingAuth = true;
  let loginToken = "";
  let loginError = "";
  let storeInitialized = false;

  async function checkAuth(t: string) {
    try {
      const headers: Record<string, string> = {};
      if (t) {
        headers["Authorization"] = `Bearer ${t}`;
      }
      const res = await fetch(`${controllerUrl}/api/v1/vhosts`, { headers });
      if (res.status === 401) {
        return { authorized: false, requiresAuth: true };
      }
      return { authorized: true, requiresAuth: false };
    } catch (e) {
      console.error("Auth check failed:", e);
      return { authorized: true, requiresAuth: false };
    }
  }

  async function verifyAndLogin() {
    loginError = "";
    if (!loginToken.trim()) {
      loginError = "Token is required.";
      return;
    }
    const check = await checkAuth(loginToken);
    if (check.authorized) {
      token.set(loginToken);
      needsLogin = false;
      if (!storeInitialized) {
        initGlobalStore(controllerUrl);
        storeInitialized = true;
      }
      toast.success("Successfully authenticated.");
    } else {
      loginError = "Invalid Admin Token.";
    }
  }

  // Subscribe to token changes
  const unsubscribeToken = token.subscribe(async (value) => {
    if (!value) {
      const check = await checkAuth("");
      if (check.requiresAuth) {
        needsLogin = true;
        storeInitialized = false;
      } else {
        needsLogin = false;
        if (!storeInitialized) {
          initGlobalStore(controllerUrl);
          storeInitialized = true;
        }
      }
    } else {
      const check = await checkAuth(value);
      if (!check.authorized) {
        token.set("");
        needsLogin = true;
        storeInitialized = false;
      } else {
        needsLogin = false;
        if (!storeInitialized) {
          initGlobalStore(controllerUrl);
          storeInitialized = true;
        }
      }
    }
    isCheckingAuth = false;
  });

  $: if ($latestLog) {
    if (
      $latestLog.action.toLowerCase() === "block" ||
      $latestLog.action.toLowerCase() === "ratelimit"
    ) {
      activeAlert = {
        client_ip: $latestLog.client_ip,
        method: $latestLog.method,
        path: $latestLog.path,
        reason: $latestLog.reason || "ATTACK PATTERN DETECTED",
        action: $latestLog.action.toUpperCase(),
      };
      dismissedAlert = false;
    }
  }

  function deployRules() {
    showDeployToast = true;
    setTimeout(() => {
      showDeployToast = false;
    }, 3000);
  }

  onDestroy(() => {
    unsubscribeToken();
    cleanupGlobalStore();
  });
</script>

{#if isCheckingAuth}
  <div class="h-screen w-screen bg-slate-950 flex items-center justify-center text-slate-400">
    <div class="flex flex-col items-center gap-3">
      <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      <p class="text-sm font-medium tracking-wide">Checking connection & authentication...</p>
    </div>
  </div>
{:else if needsLogin}
  <div
    class="h-screen w-screen bg-slate-950 flex items-center justify-center p-4 relative overflow-hidden font-sans"
  >
    <!-- Background Decorative Gradients -->
    <div
      class="absolute top-1/4 left-1/4 -translate-x-1/2 -translate-y-1/2 w-80 h-80 bg-blue-500/10 rounded-full blur-[100px] pointer-events-none"
    ></div>
    <div
      class="absolute bottom-1/4 right-1/4 translate-x-1/2 translate-y-1/2 w-80 h-80 bg-indigo-500/10 rounded-full blur-[100px] pointer-events-none"
    ></div>

    <!-- Glassmorphic Login Card -->
    <div
      class="max-w-md w-full bg-slate-900/60 backdrop-blur-xl border border-slate-800/80 rounded-2xl p-8 shadow-2xl flex flex-col items-center relative z-10 transition-all duration-300"
    >
      <!-- Logo Icon -->
      <div
        class="h-16 w-16 bg-blue-600/15 border border-blue-500/35 rounded-2xl flex items-center justify-center mb-6 shadow-inner animate-pulse"
      >
        <Shield class="text-blue-400" size={32} />
      </div>

      <h2 class="text-2xl font-bold text-slate-100 tracking-tight text-center">Aegis WAF</h2>
      <p class="text-sm text-slate-400 mt-2 mb-8 text-center max-w-[280px]">
        Enter your administration token to access the control panel.
      </p>

      <!-- Form -->
      <form on:submit|preventDefault={verifyAndLogin} class="w-full space-y-5">
        <div class="space-y-2">
          <label
            for="token-input"
            class="text-xs font-semibold text-slate-400 uppercase tracking-wider block"
            >Admin Token</label
          >
          <div class="relative">
            <span
              class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500"
            >
              <Lock size={18} />
            </span>
            <input
              id="token-input"
              type="password"
              placeholder="Enter admin token..."
              bind:value={loginToken}
              class="w-full bg-slate-950/75 border border-slate-800 focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/60 text-slate-200 placeholder-slate-600 rounded-xl py-3 pl-11 pr-4 text-sm transition-all focus:outline-none"
            />
          </div>
          {#if loginError}
            <p class="text-red-400 text-xs font-medium mt-1.5 flex items-center gap-1.5">
              <span class="inline-block w-1.5 h-1.5 bg-red-500 rounded-full"></span>
              {loginError}
            </p>
          {/if}
        </div>

        <button
          type="submit"
          class="w-full bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white font-semibold py-3 px-4 rounded-xl shadow-lg shadow-blue-900/20 hover:shadow-blue-900/35 transition-all flex items-center justify-center gap-2 group cursor-pointer text-sm border-none"
        >
          <span>Authenticate</span>
          <ArrowRight
            size={16}
            class="transform group-hover:translate-x-0.5 transition-transform"
          />
        </button>
      </form>

      <div class="mt-8 flex items-center gap-2 text-xs text-slate-500 font-medium">
        <Server size={14} />
        <span>Controller: {controllerUrl}</span>
      </div>
    </div>
  </div>
{:else}
  <Layout bind:activeTab on:deploy={deployRules}>
    {#if activeTab === "dashboard"}
      <Dashboard />
    {:else if activeTab === "threats"}
      <ThreatIntel />
    {:else if activeTab === "rules"}
      <RuleEngine />
    {:else if activeTab === "rate_limits"}
      <RateLimiting />
    {:else if activeTab === "vhosts"}
      <VHostConfig />
    {:else if activeTab === "access_control"}
      <AccessControl />
    {:else if activeTab === "ssl"}
      <SSLCertificates />
    {:else if activeTab === "nodes"}
      <AgentNodes />
    {:else if activeTab === "traffic"}
      <LiveLogs />
    {/if}
  </Layout>
{/if}

<DeployToast show={showDeployToast} />
<ToastContainer />

<AlertBanner
  show={activeAlert != null && !dismissedAlert}
  alert={activeAlert}
  on:dismiss={() => (dismissedAlert = true)}
/>
