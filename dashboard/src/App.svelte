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

  import AlertBanner from "./components/ui/AlertBanner.svelte";
  import ToastContainer from "./components/ui/ToastContainer.svelte";
  import { initGlobalStore, cleanupGlobalStore, latestLog, token } from "./lib/stores";
  import { toast } from "./lib/toast";
  import { Lock, Shield, Server, ArrowRight } from "lucide-svelte";

  const controllerUrl =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:8080";
  let activeTab =
    typeof window !== "undefined"
      ? localStorage.getItem("jarswaf_active_tab") || "dashboard"
      : "dashboard";
  $: if (typeof window !== "undefined") {
    localStorage.setItem("jarswaf_active_tab", activeTab);
  }

  let dismissedAlert = false;
  let activeAlert: any = null;

  let needsLogin = false;
  let mustChangePassword = false;
  let newPassword = "";
  let confirmPassword = "";
  let changePasswordError = "";
  let isChangingPassword = false;

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
    } catch (_e) {
      return { authorized: true, requiresAuth: false };
    }
  }

  async function verifyAndLogin() {
    loginError = "";
    if (!loginToken.trim()) {
      loginError = "Token / Password is required.";
      return;
    }

    try {
      const loginRes = await fetch(`${controllerUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: loginToken }),
      });

      if (loginRes.ok) {
        const data = await loginRes.json();
        if (data.must_change_password) {
          mustChangePassword = true;
          loginError = "";
          return;
        }

        token.set(loginToken);
        needsLogin = false;
        mustChangePassword = false;
        if (!storeInitialized) {
          initGlobalStore(controllerUrl);
          storeInitialized = true;
        }
        toast.success("Successfully authenticated.");
        return;
      }
    } catch (_e) {
      // Fall back silently
    }

    const check = await checkAuth(loginToken);
    if (check.authorized) {
      token.set(loginToken);
      needsLogin = false;
      mustChangePassword = false;
      if (!storeInitialized) {
        initGlobalStore(controllerUrl);
        storeInitialized = true;
      }
      toast.success("Successfully authenticated.");
    } else {
      loginError = "Invalid Admin Password or Token.";
    }
  }

  async function handleForcePasswordChange() {
    changePasswordError = "";
    if (!newPassword || newPassword.length < 8) {
      changePasswordError = "New password must be at least 8 characters.";
      return;
    }
    if (newPassword !== confirmPassword) {
      changePasswordError = "Passwords do not match.";
      return;
    }

    isChangingPassword = true;
    try {
      const res = await fetch(`${controllerUrl}/api/v1/auth/change-password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${loginToken}`,
        },
        body: JSON.stringify({
          old_password: loginToken,
          new_password: newPassword,
        }),
      });

      if (res.ok) {
        toast.success("Password updated successfully!");
        token.set(newPassword);
        loginToken = newPassword;
        mustChangePassword = false;
        needsLogin = false;
        if (!storeInitialized) {
          initGlobalStore(controllerUrl);
          storeInitialized = true;
        }
      } else {
        const err = await res.text();
        changePasswordError = err || "Failed to update password.";
      }
    } catch (e) {
      changePasswordError = "Network error updating password.";
    } finally {
      isChangingPassword = false;
    }
  }

  // Subscribe to token changes
  const unsubscribeToken = token.subscribe(async (value) => {
    if (!value) {
      needsLogin = true;
      storeInitialized = false;
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
{:else if mustChangePassword}
  <div
    class="h-screen w-screen bg-slate-950 flex items-center justify-center p-4 relative overflow-hidden font-sans"
  >
    <!-- Background Decorative Gradients -->
    <div
      class="absolute top-1/4 left-1/4 -translate-x-1/2 -translate-y-1/2 w-80 h-80 bg-amber-500/10 rounded-full blur-[100px] pointer-events-none"
    ></div>
    <div
      class="absolute bottom-1/4 right-1/4 translate-x-1/2 translate-y-1/2 w-80 h-80 bg-blue-500/10 rounded-full blur-[100px] pointer-events-none"
    ></div>

    <!-- Force Change Password Card -->
    <div
      class="max-w-md w-full bg-slate-900/80 backdrop-blur-xl border border-amber-500/30 rounded-2xl p-8 shadow-2xl shadow-amber-500/10 flex flex-col items-center relative z-10 transition-all duration-300"
    >
      <div
        class="h-14 w-14 bg-amber-500/15 border border-amber-500/35 rounded-2xl flex items-center justify-center mb-6 shadow-inner"
      >
        <Lock class="text-amber-400" size={28} />
      </div>

      <h2 class="text-2xl font-bold text-slate-100 tracking-tight text-center">Ubah Password Pertama Kali</h2>
      <p class="text-xs text-slate-400 mt-2 mb-6 text-center leading-relaxed">
        Anda menggunakan password awal otomatis. Demi keamanan sistem, silakan buat password baru sebelum mengakses Dashboard.
      </p>

      <form on:submit|preventDefault={handleForcePasswordChange} class="w-full space-y-4">
        <div class="space-y-2">
          <label for="new-pass" class="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Password Baru</label>
          <input
            id="new-pass"
            type="password"
            placeholder="Minimal 8 karakter..."
            bind:value={newPassword}
            class="w-full bg-slate-950/75 border border-slate-700/50 focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/60 text-slate-200 placeholder-slate-600 rounded-xl py-3 px-4 text-sm transition-all focus:outline-none"
          />
        </div>

        <div class="space-y-2">
          <label for="confirm-pass" class="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Konfirmasi Password Baru</label>
          <input
            id="confirm-pass"
            type="password"
            placeholder="Ketik ulang password baru..."
            bind:value={confirmPassword}
            class="w-full bg-slate-950/75 border border-slate-700/50 focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/60 text-slate-200 placeholder-slate-600 rounded-xl py-3 px-4 text-sm transition-all focus:outline-none"
          />
        </div>

        {#if changePasswordError}
          <p class="text-red-400 text-xs font-medium mt-1 flex items-center gap-1.5">
            <span class="inline-block w-1.5 h-1.5 bg-red-500 rounded-full"></span>
            {changePasswordError}
          </p>
        {/if}

        <button
          type="submit"
          disabled={isChangingPassword}
          class="w-full mt-2 bg-amber-600 hover:bg-amber-500 active:bg-amber-700 text-slate-950 font-bold py-3 px-5 rounded-xl shadow-lg shadow-amber-900/20 transition-all flex items-center justify-center gap-2 group cursor-pointer text-sm border-none disabled:opacity-50"
        >
          <span>{isChangingPassword ? "Memproses..." : "Simpan Password Baru"}</span>
          <ArrowRight size={16} class="transform group-hover:translate-x-0.5 transition-transform" />
        </button>
      </form>
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
      class="max-w-md w-full bg-slate-900/60 backdrop-blur-xl border border-slate-700/30 rounded-2xl p-10 shadow-2xl shadow-blue-500/5 flex flex-col items-center relative z-10 transition-all duration-300"
    >
      <!-- Logo Icon -->
      <div
        class="h-16 w-16 bg-blue-600/15 border border-blue-500/35 rounded-2xl flex items-center justify-center mb-8 shadow-inner transition-transform hover:scale-105"
      >
        <Shield class="text-blue-400" size={32} />
      </div>

      <h2 class="text-3xl font-bold text-slate-100 tracking-tight text-center">jarsWAF</h2>
      <p class="text-sm text-slate-400 mt-3 mb-10 text-center max-w-[280px]">
        Enter your administration token or password to access the control panel.
      </p>

      <!-- Form -->
      <form on:submit|preventDefault={verifyAndLogin} class="w-full space-y-6">
        <div class="space-y-3">
          <label
            for="token-input"
            class="text-xs font-semibold text-slate-400 uppercase tracking-wider block"
            >Admin Password / Token</label
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
              placeholder="Enter admin password..."
              bind:value={loginToken}
              class="w-full bg-slate-950/75 border border-slate-700/50 focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/60 text-slate-200 placeholder-slate-600 rounded-xl py-3.5 pl-12 pr-5 text-sm transition-all focus:outline-none"
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
          class="w-full bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white font-semibold py-3.5 px-5 rounded-xl shadow-lg shadow-blue-900/20 hover:shadow-blue-900/35 transition-all flex items-center justify-center gap-2 group cursor-pointer text-sm border-none"
        >
          <span>Authenticate</span>
          <ArrowRight
            size={16}
            class="transform group-hover:translate-x-0.5 transition-transform"
          />
        </button>
      </form>

      <div class="mt-10 flex items-center gap-2 text-xs text-slate-500 font-medium">
        <Server size={14} />
        <span>Controller: {controllerUrl}</span>
      </div>
    </div>
  </div>
{:else}
  <Layout bind:activeTab>
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

<ToastContainer />

<AlertBanner
  show={activeAlert != null && !dismissedAlert}
  alert={activeAlert}
  on:dismiss={() => (dismissedAlert = true)}
/>
