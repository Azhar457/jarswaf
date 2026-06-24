import { writable } from "svelte/store";

export interface WafLog {
  timestamp: string;
  client_ip: string;
  method: string;
  path: string;
  action: string;
  rule_id: string;
  reason: string;
  expanded?: boolean;
}

export interface Stats {
  total_requests: number;
  blocked: number;
  rate_limited: number;
}

export interface AgentInfo {
  hostname: string;
  ip: string;
  os: string;
  cpu: number;
  ram: number;
  disk: number;
  uptime: string;
  status: string;
  network_interfaces: any[];
  discovered_services: any[];
}

export interface VHost {
  name: string;
  hosts: string[];
  backend: string;
  rate_limit_tiers: any[];
  rules: string[];
  blocked_countries: string[];
  geoblock_type: string;
  custom_rules: any[];
  ssl: string;
  max_body: string;
  rate_limit: string;
}

export interface RateLimitPolicy {
  name: string;
  limit: string;
  burst: number;
  path: string;
  description: string;
}

export const connectionStatus = writable<"connecting" | "online" | "offline">("connecting");
export const logs = writable<WafLog[]>([]);
export const latestLog = writable<WafLog | null>(null);
export const stats = writable<Stats>({ total_requests: 0, blocked: 0, rate_limited: 0 });
export const dbSize = writable<string>("0.0 KB");
export const vhostsCount = writable<number>(0);
export const agents = writable<AgentInfo[]>([]);
export const vhostsList = writable<VHost[]>([]);
export const rateLimits = writable<RateLimitPolicy[]>([]);

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let flushInterval: ReturnType<typeof setInterval>;
let incomingQueue: WafLog[] = [];
let isInitialized = false;

export function initGlobalStore(controllerUrl: string) {
  if (isInitialized) return;
  isInitialized = true;

  // Fetch initial REST data
  fetch(`${controllerUrl}/api/v1/agents`)
    .then((res) => res.json())
    .then((data) => agents.set(data))
    .catch(console.error);

  fetch(`${controllerUrl}/api/v1/vhosts`)
    .then((res) => res.json())
    .then((data) => {
      vhostsList.set(data);
      vhostsCount.set(data.length);
    })
    .catch(console.error);

  fetch(`${controllerUrl}/api/v1/rate-limits`)
    .then((res) => res.json())
    .then((data) => rateLimits.set(data))
    .catch(console.error);

  const connectWs = () => {
    const wsUrl = controllerUrl.replace(/^http/, "ws") + "/ws/dashboard";
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      connectionStatus.set("online");
    };

    ws.onclose = () => {
      connectionStatus.set("offline");
      ws = null;
      if (!reconnectTimer) {
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null;
          connectWs();
        }, 2000);
      }
    };

    ws.onerror = () => {
      ws?.close();
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "log") {
          data.expanded = false;
          incomingQueue.push(data);
          latestLog.set(data);
        } else if (data.type === "stats") {
          stats.set({
            total_requests: data.total_requests,
            blocked: data.blocked,
            rate_limited: data.rate_limited,
          });
        }
      } catch (e) {
        // Ignore parsing errors
      }
    };
  };

  connectWs();

  flushInterval = setInterval(() => {
    if (incomingQueue.length > 0) {
      logs.update((currentLogs) => {
        const newLogs = [...incomingQueue.reverse(), ...currentLogs];
        return newLogs.slice(0, 500); // retain 500 max
      });
      incomingQueue = [];
    }
  }, 200);
}

export function cleanupGlobalStore() {
  if (ws) {
    ws.close();
    ws = null;
  }
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (flushInterval) clearInterval(flushInterval);
  isInitialized = false;
}
