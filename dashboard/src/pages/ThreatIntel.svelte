<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { Shield, ShieldAlert, Crosshair, Map, Activity, MapPin } from 'lucide-svelte';
  import Globe from '../components/ui/Globe.svelte';
  import Card from '../components/ui/Card.svelte';
  import Badge from '../components/ui/Badge.svelte';

  interface ThreatEvent {
    ip: string;
    lat: number;
    lng: number;
    rule_id: string;
    timestamp: string;
    magnitude: number;
  }

  let events: ThreatEvent[] = [];
  let globeMarkers: any[] = [];
  let loading = true;
  let pollInterval: any;

  async function fetchThreats() {
    try {
      const res = await fetch("http://localhost:8080/api/v1/threat-intel/events");
      if (res.ok) {
        events = await res.json();
        const aggregated = new Map();
        for (const e of events) {
          const key = `${e.lat.toFixed(2)},${e.lng.toFixed(2)}`;
          if (!aggregated.has(key)) {
             aggregated.set(key, { ...e, count: 1 });
          } else {
             aggregated.get(key).count += 1;
          }
        }
        globeMarkers = Array.from(aggregated.values()).map(e => ({
          location: [e.lat, e.lng],
          size: 0.05 + (e.count * 0.01),
          action: "BLOCK",
          count: e.count
        }));
      }
    } catch (e) {
      console.error("Failed to fetch threat intel events:", e);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    fetchThreats();
    pollInterval = setInterval(fetchThreats, 5000);
  });

  onDestroy(() => {
    if (pollInterval) clearInterval(pollInterval);
  });
</script>

<div class="space-y-6">
  <div>
    <h1 class="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
      <Crosshair class="text-red-500" /> Global Threat Intel
    </h1>
    <p class="text-slate-400 mt-1">Real-time visualization of malicious actors and global botnet clusters.</p>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Globe Visualization -->
    <div class="lg:col-span-2 space-y-4">
      <Card className="p-0 overflow-hidden relative bg-slate-950/50 flex flex-col h-[600px] border-slate-800">
        <div class="absolute top-4 left-4 z-10">
          <Badge variant="danger" className="animate-pulse">LIVE SYNC ACTIVE</Badge>
          <p class="text-xs font-mono text-slate-400 mt-2">Aegis Reputation Network</p>
        </div>
        
        <div class="flex-1 w-full h-full flex items-center justify-center p-8">
          {#if !loading && globeMarkers.length > 0}
            <Globe markers={globeMarkers} className="w-full max-w-lg opacity-80" speed={0.005} />
          {:else if !loading}
            <div class="text-slate-500 text-sm flex flex-col items-center">
              <Shield class="w-12 h-12 text-slate-700 mb-2 opacity-50" />
              No active threats detected.
            </div>
          {/if}
        </div>
      </Card>
    </div>

    <!-- Threat Actors List -->
    <div class="space-y-4">
      <h2 class="text-lg font-semibold text-slate-200 flex items-center gap-2">
        <ShieldAlert size={18} class="text-amber-500" /> Recent Interceptions
      </h2>
      <div class="space-y-3 max-h-[500px] overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-slate-700">
        {#if events.length > 0}
          {#each events.slice(0, 15) as actor}
            <Card className="p-4 flex flex-col gap-2 border-slate-800 hover:border-slate-700 transition-colors">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-2">
                  <span class="font-mono text-sm font-bold text-red-400">{actor.ip}</span>
                  <Badge variant="danger" className="text-[10px] px-1 py-0">{actor.rule_id}</Badge>
                </div>
                <span class="text-[10px] text-slate-500">{new Date(actor.timestamp).toLocaleTimeString()}</span>
              </div>
              <div class="flex items-center gap-1.5 text-xs text-slate-400">
                <MapPin class="w-3 h-3 text-slate-500" />
                <span>{actor.lat.toFixed(2)}, {actor.lng.toFixed(2)}</span>
              </div>
            </Card>
          {/each}
        {:else if !loading}
          <div class="text-center py-6 text-slate-500 text-sm">Quiet right now.</div>
        {/if}
      </div>

      <Card className="mt-6 p-4 border-blue-500/20 bg-blue-500/5">
        <h3 class="text-sm font-bold text-slate-200 mb-2 flex items-center gap-2">
          <Activity size={16} class="text-blue-400" /> Network Sync Status
        </h3>
        <p class="text-xs text-slate-400 leading-relaxed">
          The Aegis Reputation Network is currently distributing blocklist updates to all your Agent Nodes.
        </p>
      </Card>
    </div>
  </div>
</div>
