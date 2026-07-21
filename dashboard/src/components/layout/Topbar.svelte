<script lang="ts">
  import { createEventDispatcher, onMount } from "svelte";
  import { Bell, Search, Settings, Shield, ShieldAlert, LogOut, Menu } from "lucide-svelte";
  import { wafEnabled, toggleWafStatus, token } from "../../lib/stores";
  import { toast } from "../../lib/toast";

  export let systemStatus: "online" | "offline" | "degraded" = "online";

  const dispatch = createEventDispatcher();
  const controllerUrl =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:8080";

  let toggling = false;
  let activeTheme = "dark";

  onMount(() => {
    activeTheme = localStorage.getItem("jarswaf-theme") || "dark";
    document.documentElement.className = "theme-" + activeTheme;
  });

  function setTheme(themeName: string) {
    activeTheme = themeName;
    document.documentElement.className = "theme-" + themeName;
    localStorage.setItem("jarswaf-theme", themeName);
    window.dispatchEvent(new CustomEvent("theme-changed", { detail: themeName }));
    toast.success(`Theme switched to ${themeName}.`);
  }

  async function handleWafToggle() {
    toggling = true;
    const nextState = !$wafEnabled;
    const success = await toggleWafStatus(controllerUrl, nextState);
    if (success) {
      if (nextState) {
        toast.success("jarsWAF inspection started successfully.");
      } else {
        toast.warning("jarsWAF bypassed. Traffic is flowing uninspected.");
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
  class="h-16 bg-bg-secondary border-b border-border-subtle flex items-center justify-between px-4 md:px-6 sticky top-0 z-10"
>
  <div class="flex items-center gap-2 md:gap-4">
    <!-- Burger Menu Button for Mobile & Tablet -->
    <button
      on:click={() => dispatch("toggleMobileSidebar")}
      class="lg:hidden text-text-muted hover:text-text-primary transition-colors p-2 rounded-lg hover:bg-surface-hover/30 border-none bg-transparent cursor-pointer flex items-center justify-center"
      title="Toggle Navigation Menu"
    >
      <Menu size={20} />
    </button>

    <div
      class="flex items-center gap-2 px-3 py-1.5 bg-bg-tertiary/60 rounded-full border border-border-default shrink-0"
    >
      <div
        class={`w-2 h-2 rounded-full ${
          systemStatus === "online"
            ? "bg-success shadow-[0_0_8px_rgba(16,185,129,0.8)]"
            : systemStatus === "degraded"
              ? "bg-warning shadow-[0_0_8px_rgba(245,158,11,0.8)]"
              : "bg-error shadow-[0_0_8px_rgba(239,68,68,0.8)]"
        }`}
      ></div>
      <span class="text-[10px] sm:text-xs font-semibold text-text-secondary uppercase tracking-wider">
        <span class="hidden sm:inline">System </span>{systemStatus}
      </span>
    </div>
  </div>

  <div class="flex items-center gap-2 sm:gap-4">
    <!-- WAF Status Toggle Button -->
    <button
      on:click={handleWafToggle}
      disabled={toggling}
      class={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-sm font-medium transition-all shadow-md cursor-pointer border shrink-0 ${
        $wafEnabled
          ? "bg-success-bg hover:bg-success/15 text-success border-success-border"
          : "bg-error-bg hover:bg-error/15 text-error border-error-border"
      }`}
      title={$wafEnabled
        ? "WAF is active. Click to bypass inspection."
        : "WAF is bypassed. Click to enable inspection."}
    >
      {#if $wafEnabled}
        <Shield size={16} />
        <span class="hidden sm:inline">WAF: Running</span>
        <span class="sm:hidden">Running</span>
      {:else}
        <ShieldAlert size={16} />
        <span class="hidden sm:inline">WAF: Bypassed</span>
        <span class="sm:hidden">Bypassed</span>
      {/if}
    </button>

    <!-- Theme Switcher Dots -->
    <div class="flex items-center gap-1 px-1">
      <button 
        on:click={() => setTheme('dark')} 
        class={`w-3.5 h-3.5 rounded-full bg-[#030712] border border-slate-700 transition-all hover:scale-125 focus:outline-none cursor-pointer ${activeTheme === 'dark' ? 'ring-2 ring-offset-2 ring-blue-500 scale-110' : ''}`} 
        title="Dark Theme"
      ></button>
      <button 
        on:click={() => setTheme('light')} 
        class={`w-3.5 h-3.5 rounded-full bg-[#f9fafb] border border-gray-300 transition-all hover:scale-125 focus:outline-none cursor-pointer ${activeTheme === 'light' ? 'ring-2 ring-offset-2 ring-blue-500 scale-110' : ''}`} 
        title="Light Theme"
      ></button>
      <button 
        on:click={() => setTheme('orange')} 
        class={`w-3.5 h-3.5 rounded-full bg-[#f97316] border border-orange-600 transition-all hover:scale-125 focus:outline-none cursor-pointer ${activeTheme === 'orange' ? 'ring-2 ring-offset-2 ring-orange-500 scale-110' : ''}`} 
        title="Orange Theme"
      ></button>
      <button 
        on:click={() => setTheme('sea')} 
        class={`w-3.5 h-3.5 rounded-full bg-[#0ea5e9] border border-teal-600 transition-all hover:scale-125 focus:outline-none cursor-pointer ${activeTheme === 'sea' ? 'ring-2 ring-offset-2 ring-teal-500 scale-110' : ''}`} 
        title="Sea Theme"
      ></button>
    </div>

    {#if $token}
      <button
        on:click={handleLogout}
        class="text-text-muted hover:text-error transition-colors p-2 cursor-pointer border-none bg-transparent"
        title="Logout Session"
      >
        <LogOut size={18} />
      </button>
    {/if}
  </div>
</header>
