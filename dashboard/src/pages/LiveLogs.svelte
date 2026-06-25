<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { Download, Trash2, Terminal as TerminalIcon } from "lucide-svelte";
  import { logs, latestLog } from "../lib/stores";
  import Card from "../components/ui/Card.svelte";
  import { Terminal } from "@xterm/xterm";
  import { FitAddon } from "@xterm/addon-fit";
  import "@xterm/xterm/css/xterm.css";

  const controllerUrl =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:8080";

  let terminalElement: HTMLDivElement;
  let term: Terminal;
  let fitAddon: FitAddon;
  let resizeObserver: ResizeObserver;
  let unsubscribeLogs: () => void;

  function formatTime(timestamp: string): string {
    try {
      if (timestamp.includes("T")) {
        const parts = timestamp.split("T");
        const timePart = parts[1].split(".")[0];
        return `${parts[0]} ${timePart}`;
      }
      return timestamp;
    } catch {
      return timestamp;
    }
  }

  function writeLogToTerminal(log: any) {
    if (!term) return;

    const timeStr = formatTime(log.timestamp);
    const action = (log.action || "INFO").toUpperCase();
    const method = (log.method || "GET").toUpperCase();
    const path = log.path || "/";
    const ip = log.client_ip || "unknown";
    const reason = log.reason || "";

    let tagColor = "\x1b[1;32m"; // Bold green for PASS/ALLOW
    if (action === "BLOCK" || action === "DENY") {
      tagColor = "\x1b[1;31m"; // Bold red
    } else if (action === "LIMIT" || action === "RATE_LIMIT" || action === "RATELIMIT") {
      tagColor = "\x1b[1;33m"; // Bold yellow
    }

    const displayPath = path.length > 40 ? path.slice(0, 37) + "..." : path;

    const actionTag = `${tagColor}[${action}]\x1b[0m`;
    const timeTag = `\x1b[90m[${timeStr}]\x1b[0m`;
    const methodTag = `\x1b[1;36m${method}\x1b[0m`;
    const pathTag = `\x1b[37m${displayPath}\x1b[0m`;
    const ipTag = `\x1b[1;35m${ip}\x1b[0m`;
    const reasonTag = reason ? ` \x1b[33m(${reason})\x1b[0m` : "";

    term.writeln(`${actionTag} ${timeTag} ${methodTag} ${pathTag} — ${ipTag}${reasonTag}`);
  }

  async function handleExport() {
    try {
      window.location.href = `${controllerUrl}/api/v1/logs/export`;
    } catch (e) {
      console.error("Export logs error:", e);
      alert("Failed to export logs");
    }
  }

  async function handleClear() {
    if (
      confirm(
        "Are you sure you want to clear all logs? This will truncate the ClickHouse database.",
      )
    ) {
      try {
        const res = await fetch(`${controllerUrl}/api/v1/logs/clear`, { method: "POST" });
        if (res.ok) {
          logs.set([]);
          if (term) {
            term.clear();
            term.writeln("\x1b[32m[SYSTEM]\x1b[0m Logs cleared successfully.");
          }
        }
      } catch (e) {
        console.error("Clear logs error:", e);
        alert("Failed to clear logs");
      }
    }
  }

  onMount(() => {
    // Initialize Xterm.js Terminal with CMD palette
    term = new Terminal({
      theme: {
        background: "#0c0c0c",
        foreground: "#cccccc",
        cursor: "#ffffff",
        black: "#000000",
        red: "#ff3b30",
        green: "#4cd964",
        yellow: "#ffcc00",
        blue: "#007aff",
        magenta: "#ff2d55",
        cyan: "#5ac8fa",
        white: "#ffffff",
      },
      fontFamily: "JetBrains Mono, Consolas, monospace",
      fontSize: 12.5,
      lineHeight: 1.4,
      cursorBlink: true,
      disableStdin: true,
      convertEol: true,
      scrollback: 5000,
    });

    fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalElement);

    setTimeout(() => {
      if (fitAddon) fitAddon.fit();
    }, 50);

    // Write Windows CMD welcome banner
    term.writeln("Microsoft Windows [Version 10.0.22631.3737]");
    term.writeln("(c) Microsoft Corporation. All rights reserved.");
    term.writeln("");
    term.writeln("C:\\AegisWAF> aegis-waf --stream --verbose");
    term.writeln("\x1b[32m[SYSTEM]\x1b[0m Aegis WAF Engine connected. Streaming real-time proxy events...");
    term.writeln("");

    // Print existing logs history (reversing to show oldest first)
    const initialLogs = [...$logs].reverse();
    initialLogs.forEach((log) => {
      if (term) writeLogToTerminal(log);
    });

    // Auto-fit on resize
    resizeObserver = new ResizeObserver(() => {
      if (fitAddon) {
        try {
          fitAddon.fit();
        } catch (e) {
          // Ignore fit errors when element is hidden
        }
      }
    });
    resizeObserver.observe(terminalElement);

    // Subscribe to latest log store
    unsubscribeLogs = latestLog.subscribe((log) => {
      if (log && term) {
        writeLogToTerminal(log);
      }
    });
  });

  onDestroy(() => {
    if (unsubscribeLogs) unsubscribeLogs();
    if (resizeObserver) {
      resizeObserver.disconnect();
    }
    if (term) {
      term.dispose();
    }
  });
</script>

<div class="space-y-6 h-full flex flex-col min-h-0">
  <div class="flex justify-between items-center shrink-0">
    <div>
      <h1 class="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
        <TerminalIcon class="text-blue-500" /> Live Security Terminal
      </h1>
      <p class="text-slate-400 mt-1">Real-time stream of all firewall events and requests.</p>
    </div>
    <div class="flex gap-3">
      <button
        on:click={handleExport}
        class="bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium px-4 py-2 rounded-lg transition-colors border border-slate-700 flex items-center gap-2 cursor-pointer"
      >
        <Download size={16} />
        Export
      </button>
      <button
        on:click={handleClear}
        class="bg-slate-800 hover:bg-slate-700 text-red-400 hover:text-red-300 text-sm font-medium px-4 py-2 rounded-lg transition-colors border border-slate-700 flex items-center gap-2 cursor-pointer"
      >
        <Trash2 size={16} />
        Clear
      </button>
    </div>
  </div>

  <Card className="p-0 flex-1 min-h-0 overflow-hidden flex flex-col bg-[#0c0c0c] border-slate-800 shadow-2xl rounded-xl">
    <!-- CMD Window Title Bar -->
    <div class="h-9 bg-[#1e1e1e] border-b border-slate-800 flex items-center justify-between px-4 shrink-0 rounded-t-xl select-none">
      <div class="flex items-center gap-2">
        <TerminalIcon size={14} class="text-slate-400" />
        <span class="text-xs font-medium text-slate-300 font-mono">Command Prompt - aegis-waf --stream</span>
      </div>
      <!-- Mock Window Controls -->
      <div class="flex items-center gap-2.5">
        <div class="w-2.5 h-2.5 rounded-full bg-slate-700/60 hover:bg-slate-600 transition-colors"></div>
        <div class="w-2.5 h-2.5 rounded-full bg-slate-700/60 hover:bg-slate-600 transition-colors"></div>
        <div class="w-2.5 h-2.5 rounded-full bg-red-500/80 hover:bg-red-500 transition-colors"></div>
      </div>
    </div>
    <div class="p-4 flex-1 min-h-0 overflow-hidden flex flex-col bg-[#0c0c0c]">
      <div bind:this={terminalElement} class="w-full h-full flex-1 min-h-0"></div>
    </div>
  </Card>
</div>

<style>
  :global(.xterm) {
    padding: 8px;
  }
</style>
