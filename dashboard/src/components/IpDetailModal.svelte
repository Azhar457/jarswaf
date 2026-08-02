<script lang="ts">
  import { X, ShieldAlert, ShieldCheck, MapPin, Network, Activity, Cpu } from "lucide-svelte";
  import Badge from "./ui/Badge.svelte";
  import Button from "./ui/Button.svelte";
  import Card from "./ui/Card.svelte";

  export let show = false;
  export let ip = "";
  export let country = "ID";
  export let onClose = () => {};

  // Simulated / Computed IP Intelligence Data
  $: isDatacenter = ip.startsWith("37.") || ip.startsWith("45.") || ip.startsWith("104.");
  $: riskScore = isDatacenter ? 85 : 15;
  $: unmaskedIp = isDatacenter ? "180.252.14.88" : null;
  $: verdict = riskScore > 50 ? "Commercial VPN / Unmasked Proxy" : "Direct Residential (Clean)";

  $: testMatrix = [
    { name: "Header Leakage Test", status: "PASS", score: "0 pts", desc: "No proxy headers (X-Forwarded-For) leaked" },
    { name: "rDNS PTR Record Test", status: isDatacenter ? "FAIL" : "PASS", score: isDatacenter ? "+15 pts" : "0 pts", desc: isDatacenter ? "No ISP PTR record (Datacenter range)" : "Valid ISP PTR record" },
    { name: "WIMIA Socket Mismatch", status: isDatacenter ? "FAIL" : "PASS", score: isDatacenter ? "+25 pts" : "0 pts", desc: isDatacenter ? "L4 Socket vs HTTP payload mismatch" : "Socket matches client IP" },
    { name: "Geo-Timezone Anomaly", status: isDatacenter ? "FAIL" : "PASS", score: isDatacenter ? "+15 pts" : "0 pts", desc: isDatacenter ? "Timezone Asia/Jakarta vs IP Location (NL)" : "Timezone matches location" },
    { name: "WebRTC ICE Candidate Leak", status: isDatacenter ? "FAIL" : "PASS", score: isDatacenter ? "+30 pts" : "0 pts", desc: isDatacenter ? "Leaked Real IP: 180.252.14.88" : "No ICE candidate leakage" },
    { name: "JA4 TLS Fingerprint", status: "PASS", score: "0 pts", desc: "Standard Browser TLS ClientHello" }
  ];

  function handleClose() {
    onClose();
  }
</script>

{#if show}
  <div class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl overflow-hidden relative space-y-6">
      
      <!-- Header -->
      <div class="flex items-center justify-between border-b border-slate-800 pb-4">
        <div class="flex items-center gap-3">
          <div class="p-2.5 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400">
            <ShieldAlert size={20} />
          </div>
          <div>
            <h2 class="text-xl font-bold text-slate-100 flex items-center gap-2">
              IP Intelligence Detail: <span class="font-mono text-blue-400">{ip}</span>
            </h2>
            <p class="text-xs text-slate-400">Anonymity Risk Assessment & WebRTC Unmasking Report</p>
          </div>
        </div>
        <button on:click={handleClose} class="text-slate-400 hover:text-slate-200 p-1 rounded-lg hover:bg-slate-800 transition-colors">
          <X size={20} />
        </button>
      </div>

      <!-- Risk Score & Verdict Banner -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="p-4 bg-slate-950 border-slate-800 flex items-center justify-between">
          <div>
            <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Composite Risk Score</span>
            <div class="text-3xl font-extrabold font-mono mt-1 {riskScore > 50 ? 'text-red-500' : 'text-emerald-400'}">
              {riskScore}/100
            </div>
          </div>
          <Badge variant={riskScore > 50 ? "danger" : "success"} className="text-xs">
            {riskScore > 50 ? "CRITICAL RISK" : "LOW RISK"}
          </Badge>
        </Card>

        <Card className="p-4 bg-slate-950 border-slate-800 flex flex-col justify-center">
          <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Classification Verdict</span>
          <span class="text-sm font-bold text-slate-200 mt-1 flex items-center gap-2">
            {#if riskScore > 50}
              <ShieldAlert size={16} class="text-amber-400" />
            {:else}
              <ShieldCheck size={16} class="text-emerald-400" />
            {/if}
            {verdict}
          </span>
        </Card>
      </div>

      <!-- Network Metadata & Unmasked IP Section -->
      <div class="space-y-3">
        <h3 class="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
          <Network size={14} class="text-blue-400" /> Network Metadata & Identity Correlation
        </h3>
        <Card className="p-4 bg-slate-950/60 border-slate-800 space-y-2 font-mono text-xs text-slate-300">
          <div class="flex justify-between">
            <span class="text-slate-500">Target IP Address:</span>
            <span class="text-slate-200 font-bold">{ip} ({country})</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-500">Network Type:</span>
            <span class={isDatacenter ? "text-amber-400" : "text-emerald-400"}>
              {isDatacenter ? "Datacenter / Commercial Hosting" : "Residential Broadband"}
            </span>
          </div>
          {#if unmaskedIp}
            <div class="flex justify-between border-t border-slate-800 pt-2 text-emerald-400 font-bold">
              <span>WebRTC Unmasked Real IP:</span>
              <span class="bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                🇮🇩 {unmaskedIp} (Telkomsel / Indihome)
              </span>
            </div>
          {/if}
        </Card>
      </div>

      <!-- Detailed Test Matrix Breakdown -->
      <div class="space-y-3">
        <h3 class="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
          <Activity size={14} class="text-purple-400" /> Anonymity Test Decomposition
        </h3>
        <div class="space-y-2 max-h-48 overflow-y-auto pr-1">
          {#each testMatrix as item}
            <div class="p-2.5 rounded-xl bg-slate-950/40 border border-slate-800/80 flex items-center justify-between text-xs">
              <div class="space-y-0.5">
                <span class="font-semibold text-slate-200">{item.name}</span>
                <p class="text-[11px] text-slate-400">{item.desc}</p>
              </div>
              <div class="flex items-center gap-2">
                <span class="font-mono text-[11px] text-slate-400">{item.score}</span>
                <Badge variant={item.status === "PASS" ? "success" : "danger"} className="text-[10px] px-1.5 py-0.5">
                  {item.status}
                </Badge>
              </div>
            </div>
          {/each}
        </div>
      </div>

      <!-- Modal Footer -->
      <div class="flex justify-end gap-3 border-t border-slate-800 pt-4">
        <Button variant="secondary" on:click={handleClose}>Close</Button>
        <Button variant="danger" on:click={() => alert(`IP ${ip} added to blocklist`)}>Block IP</Button>
      </div>

    </div>
  </div>
{/if}
