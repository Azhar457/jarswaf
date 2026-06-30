import { writable, get } from "svelte/store";

export interface CustomRule {
  id: string;
  name: string;
  condition_type: string;
  operator: string;
  condition_value: string;
  action: string;
  action_value: string;
  enabled: boolean;
}

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
  custom_rules: string[]; // List of custom rule IDs
  ssl: string;
  max_body: string;
  rate_limit: string;
  is_default?: boolean;
  allowlists?: any[];
  blacklists?: any[];
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
export const customRulesList = writable<CustomRule[]>([]);
export const wafEnabled = writable<boolean>(true);
export const token = writable<string>(
  typeof window !== "undefined" ? localStorage.getItem("jarswaf_token") || "" : "",
);

if (typeof window !== "undefined") {
  token.subscribe((val) => {
    localStorage.setItem("jarswaf_token", val);
  });
}

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let flushInterval: ReturnType<typeof setInterval>;
let incomingQueue: WafLog[] = [];
let isInitialized = false;

export function initGlobalStore(controllerUrl: string) {
  if (isInitialized) return;
  isInitialized = true;

  const currentToken = get(token);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (currentToken) {
    headers["Authorization"] = `Bearer ${currentToken}`;
  }

  const checkStatus = (res: Response) => {
    if (res.status === 401) {
      token.set("");
      isInitialized = false;
      cleanupGlobalStore();
      throw new Error("Unauthorized");
    }
    return res;
  };

  // Fetch initial REST data
  fetch(`${controllerUrl}/api/v1/agents`, { headers })
    .then(checkStatus)
    .then((res) => res.json())
    .then((data) => agents.set(data))
    .catch(console.error);

  fetch(`${controllerUrl}/api/v1/vhosts`, { headers })
    .then(checkStatus)
    .then((res) => res.json())
    .then((data) => {
      vhostsList.set(data);
      vhostsCount.set(data.length);
    })
    .catch(console.error);

  fetch(`${controllerUrl}/api/v1/rate-limits`, { headers })
    .then(checkStatus)
    .then((res) => res.json())
    .then((data) => rateLimits.set(data))
    .catch(console.error);

  fetch(`${controllerUrl}/api/v1/custom-rules`, { headers })
    .then(checkStatus)
    .then((res) => res.json())
    .then((data) => customRulesList.set(data))
    .catch(console.error);

  fetch(`${controllerUrl}/api/v1/logs`, { headers })
    .then(checkStatus)
    .then((res) => res.json())
    .then((data) => logs.set(data))
    .catch(console.error);

  fetch(`${controllerUrl}/api/v1/logs/db_size`, { headers })
    .then(checkStatus)
    .then((res) => res.json())
    .then((data) => dbSize.set(data.formatted || "0.0 KB"))
    .catch(console.error);

  fetch(`${controllerUrl}/api/v1/config`, { headers })
    .then(checkStatus)
    .then((res) => res.json())
    .then((data) => wafEnabled.set(data.waf_enabled))
    .catch(console.error);

  const connectWs = () => {
    const wsToken = get(token);
    const wsUrl = controllerUrl.replace(/^http/, "ws") + "/ws/dashboard";

    ws = wsToken ? new WebSocket(wsUrl, [wsToken]) : new WebSocket(wsUrl);

    ws.onopen = () => {
      connectionStatus.set("online");
    };

    ws.onclose = () => {
      connectionStatus.set("offline");
      ws = null;
      if (!reconnectTimer && isInitialized) {
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

export async function toggleWafStatus(controllerUrl: string, enabled: boolean) {
  const currentToken = get(token);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (currentToken) {
    headers["Authorization"] = `Bearer ${currentToken}`;
  }

  try {
    const res = await fetch(`${controllerUrl}/api/v1/config`, { headers });
    if (res.ok) {
      const data = await res.json();
      const payload = {
        logging_enabled: data.logging_enabled,
        log_limit_mb: data.log_limit_mb,
        waf_enabled: enabled,
      };

      const postRes = await fetch(`${controllerUrl}/api/v1/config`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      });
      if (postRes.ok) {
        wafEnabled.set(enabled);
        return true;
      }
    }
  } catch (e) {
    console.error("Failed to toggle WAF status:", e);
  }
  return false;
}
