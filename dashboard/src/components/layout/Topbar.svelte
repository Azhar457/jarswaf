<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { Bell, Search, Settings, Shield, ShieldAlert, LogOut } from "lucide-svelte";
  import { wafEnabled, toggleWafStatus, token } from "../../lib/stores";
  import { toast } from "../../lib/toast";

  export let systemStatus: "online" | "offline" | "degraded" = "online";

  const dispatch = createEventDispatcher();
  const controllerUrl =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:8080";

  let toggling = false;

  async function handleWafToggle() {
    toggling = true;
    const nextState = !$wafEnabled;
    const success = await toggleWafStatus(controllerUrl, nextState);
    if (success) {
      if (nextState) {
        toast.success("Aegis WAF inspection started successfully.");
      } else {
        toast.warning("Aegis WAF bypassed. Traffic is flowing uninspected.");
      }
    } else {
      toast.error("Failed to update WAF status.");
    }
    toggling = false;
  }

  function handleLogout() {
    token.set("");
    toast.success("Logged out successfully.");
  }
</script>

<header
  class="h-16 bg-slate-950 border-b border-slate-800 flex items-center justify-between px-6 sticky top-0 z-10"
>
  <div class="flex items-center gap-4">
    <div
      class="flex items-center gap-2 px-3 py-1.5 bg-slate-900 rounded-full border border-slate-800"
    >
      <div
        class={`w-2 h-2 rounded-full ${
          systemStatus === "online"
            ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]"
            : systemStatus === "degraded"
              ? "bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.8)]"
              : "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]"
        }`}
      ></div>
      <span class="text-xs font-medium text-slate-300 uppercase tracking-wide">
        System {systemStatus}
      </span>
    </div>
  </div>

  <div class="flex items-center gap-4">
    <!-- WAF Status Toggle Button -->
    <button
      on:click={handleWafToggle}
      disabled={toggling}
      class={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-sm font-medium transition-all shadow-md cursor-pointer border ${
        $wafEnabled
          ? "bg-emerald-600/10 hover:bg-emerald-600/20 text-emerald-400 border-emerald-500/30"
          : "bg-red-600/10 hover:bg-red-600/20 text-red-400 border-red-500/30"
      }`}
      title={$wafEnabled
        ? "WAF is active. Click to bypass inspection."
        : "WAF is bypassed. Click to enable inspection."}
    >
      {#if $wafEnabled}
        <Shield size={16} />
        <span>WAF: Running</span>
      {:else}
        <ShieldAlert size={16} />
        <span>WAF: Bypassed</span>
      {/if}
    </button>

    <div class="relative hidden md:block">
      <Search class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
      <input
        type="text"
        placeholder="Search logs, IPs, rules..."
        class="bg-slate-900 border border-slate-800 text-slate-200 text-sm rounded-lg pl-9 pr-4 py-1.5 focus:outline-none focus:border-blue-500 transition-colors w-64"
      />
    </div>

    <button class="text-slate-400 hover:text-slate-100 transition-colors p-2">
      <Bell size={18} />
    </button>
    <button class="text-slate-400 hover:text-slate-100 transition-colors p-2">
      <Settings size={18} />
    </button>

    <div class="h-6 w-px bg-slate-800 mx-1"></div>

    <button
      class="bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-4 py-1.5 rounded-lg transition-colors shadow-[0_0_15px_rgba(37,99,235,0.3)] hover:shadow-[0_0_20px_rgba(37,99,235,0.5)] border-none"
      on:click={() => dispatch("deploy")}
    >
      Deploy Rules
    </button>

    {#if $token}
      <button
        on:click={handleLogout}
        class="text-slate-400 hover:text-red-400 transition-colors p-2 cursor-pointer border-none bg-transparent"
        title="Logout Session"
      >
        <LogOut size={18} />
      </button>
    {/if}
  </div>
</header>
