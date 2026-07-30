#!/bin/bash
# jarsWAF CLI - Management wrapper for jarsWAF Agent
set -euo pipefail

INSTALL_DIR="/opt/jarswaf"
BINARY="${INSTALL_DIR}/agent"
CONFIG="${INSTALL_DIR}/config.toml"
LOGFILE="${INSTALL_DIR}/logs/jarswaf.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

usage() {
    echo -e "${BOLD}jarsWAF CLI — Web Application Firewall${NC}"
    echo ""
    echo "Usage:  jarswaf <command> [options]"
    echo ""
    echo "Commands:"
    echo "  start                     Start the WAF agent"
    echo "  stop                      Stop the WAF agent"
    echo "  restart                   Restart the WAF agent"
    echo "  status                    Show agent status (PID, uptime, port)"
    echo ""
    echo "  config view               View current config"
    echo "  config edit               Edit config in \$EDITOR"
    echo "  config set <key> <val>    Set a config value (e.g., port_http 9090)"
    echo ""
    echo "  logs [options]            View agent logs"
    echo "    --tail, -f              Follow log (tail -f)"
    echo "    --lines=N, -n N         Show last N lines (default: 30)"
    echo ""
    echo "  install [--controller=URL]  Install/upgrade jarsWAF"
    echo "  uninstall                   Remove jarsWAF completely"
    echo ""
    echo "  version                   Show version"
    echo "  help                      Show this help"
}

# ── Helpers ──
require_root() { if [[ $EUID -ne 0 ]]; then echo -e "${RED}❌ Root required${NC}" >&2; exit 1; fi; }
agent_pids() { pgrep -x agent 2>/dev/null || true; }
agent_first_pid() { agent_pids | head -1; }
agent_running() { [[ -n "$(agent_first_pid)" ]]; }

kill_all_agents() {
    local pids=$(agent_pids)
    [[ -z "$pids" ]] && return 0
    echo -e "${CYAN}🛑 Stopping jarsWAF...${NC}"
    # Graceful kill all
    echo "$pids" | xargs -r kill 2>/dev/null || true
    sleep 2
    local remaining=$(agent_pids)
    if [[ -n "$remaining" ]]; then
        echo "$remaining" | xargs -r kill -9 2>/dev/null || true
        sleep 1
    fi
    if agent_running; then
        echo -e "${RED}❌ Could not stop agents: $(agent_pids | tr '\n' ' ')${NC}" >&2
        return 1
    fi
    echo -e "${GREEN}✅ Stopped${NC}"
}

# ── Commands ──

cmd_start() {
    if agent_running; then
        echo -e "${YELLOW}⚠️  jarsWAF already running${NC}"
        return 0
    fi
    require_root
    mkdir -p "${INSTALL_DIR}/logs" "${INSTALL_DIR}/certs"
    nohup "${BINARY}" --config "${CONFIG}" > "${INSTALL_DIR}/agent.log" 2>&1 &
    local pid=$!
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        echo -e "${GREEN}✅ jarsWAF started (PID $pid)${NC}"
    else
        echo -e "${RED}❌ Failed to start${NC}"
        tail -5 "${INSTALL_DIR}/agent.log" 2>/dev/null
        exit 1
    fi
}

cmd_stop() {
    if ! agent_running; then
        echo -e "${YELLOW}⚠️  jarsWAF not running${NC}"
        return 0
    fi
    kill_all_agents
}

cmd_restart() {
    kill_all_agents || true
    sleep 1
    cmd_start
}

cmd_status() {
    echo -e "${BOLD}⚙️  jarsWAF Status${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━${NC}"
    if agent_running; then
        local pid=$(agent_first_pid)
        echo -e "  PID:       ${GREEN}${pid}${NC}"
        echo -e "  Uptime:    $(ps -o etime= -p "$pid" 2>/dev/null | xargs)"
        local port=$(ss -tlnp 2>/dev/null | grep "pid=${pid}" | awk '{print $4}' | cut -d: -f2 | head -1)
        [[ -n "$port" ]] && echo -e "  Port:      ${CYAN}${port}${NC}" || echo -e "  Port:      ${YELLOW}?${NC}"
        echo -e "  Status:    ${GREEN}● Running${NC}"
    else
        echo -e "  Status:    ${RED}○ Stopped${NC}"
    fi
    echo -e "  Binary:    ${BINARY}"
    echo -e "  Config:    ${CONFIG}"
    echo -e "  Log:       ${LOGFILE}"
    echo -e "  Install:   ${INSTALL_DIR}"
}

cmd_config() {
    local sub="${1:-view}"
    [[ $# -gt 0 ]] && shift
    case "$sub" in
        view)
            if [[ -f "$CONFIG" ]]; then
                cat "$CONFIG"
            else
                echo -e "${RED}❌ Config not found: ${CONFIG}${NC}" >&2
                exit 1
            fi
            ;;
        edit)
            ${EDITOR:-vi} "$CONFIG"
            echo -e "${GREEN}✅ Config saved${NC}"
            ;;
        set)
            local key="${1:-}"
            local val="${2:-}"
            if [[ -z "$key" || -z "$val" ]]; then
                echo -e "${RED}Usage: jarswaf config set <key> <value>${NC}" >&2
                echo -e "${YELLOW}  Example: jarswaf config set waf_enabled false${NC}" >&2
                exit 1
            fi
            # Known boolean keys — write without quotes
            local bool_keys="waf_enabled metrics_push_interval_secs"
            local fmt_val
            if echo " $bool_keys " | grep -q " $key "; then
                fmt_val="$val"
            else
                fmt_val="\"${val}\""
            fi
            if grep -qP "^\s*${key}\s*=" "$CONFIG"; then
                sed -i "s|^\(${key}\s*=\).*|\1 ${fmt_val}|" "$CONFIG"
                echo -e "${GREEN}✅ Set ${key} = ${fmt_val}${NC}"
            else
                echo -e "${RED}❌ Key '${key}' not found in config${NC}" >&2
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}Unknown: jarswaf config ${sub}${NC}" >&2
            echo "Usage: jarswaf config {view|edit|set}" >&2
            exit 1
            ;;
    esac
}

cmd_logs() {
    local lines=30
    local follow=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tail|-f) follow="-f"; shift ;;
            --lines=*) lines="${1#*=}"; shift ;;
            -n) shift; lines="${1:-30}"; shift ;;
            *) shift ;;
        esac
    done
    if [[ ! -f "$LOGFILE" ]]; then
        echo -e "${YELLOW}⚠️  No log file yet (${LOGFILE})${NC}" >&2
        exit 1
    fi
    if [[ -n "$follow" ]]; then
        tail -f "$LOGFILE"
    else
        tail -n "$lines" "$LOGFILE"
    fi
}

cmd_install() {
    local controller_url=""
    for arg; do [[ "$arg" == --controller=* ]] && controller_url="${arg#*=}"; done

    echo -e "${CYAN}🔍 Fetching latest release...${NC}"
    local repo="Azhar457/jarswaf"
    local latest=$(curl -s "https://api.github.com/repos/${repo}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
    [[ -z "$latest" ]] && { echo -e "${YELLOW}⚠️  Using default: v0.2.3${NC}"; latest="v0.2.3"; }
    echo -e "${GREEN}✅ Release: ${BOLD}${latest}${NC}"

    local url="https://github.com/${repo}/releases/download/${latest}/jarswaf-${latest#v}-musl.tar.gz"
    local tmp="/tmp/jarswaf-install.tar.gz"
    echo -e "${CYAN}⬇️  Downloading ${latest}...${NC}"
    curl -fsSLk -o "$tmp" "$url" || { echo -e "${RED}❌ Download failed${NC}"; exit 1; }

    echo -e "${CYAN}📦 Extracting...${NC}"
    sudo mkdir -p "${INSTALL_DIR}"
    sudo tar -xzf "$tmp" -C "${INSTALL_DIR}"
    sudo chmod 755 "${INSTALL_DIR}/agent" "${INSTALL_DIR}/jarswaf" 2>/dev/null
    rm -f "$tmp"
    echo -e "${GREEN}✅ Binary installed${NC}"

    if [[ ! -f "$CONFIG" ]]; then
        echo -e "${CYAN}⚙️  Creating default config...${NC}"
        sudo tee "$CONFIG" > /dev/null << 'TOML'
certificates = []
allowlists = []
blacklists = []

[global]
port_http = 8000
port_https = 8443
max_body_size = 10485760
default_rate_limit = 600
log_dir = "/opt/jarswaf/logs"
log_level = "info"
admin_token = "[REDACTED-CREDENTIAL]"
waf_enabled = true
webhooks = []
metrics_push_interval_secs = 0

[tls]
mode = "disabled"
cert_dir = "/opt/jarswaf/certs"

[logging]
mode = "file"
log_path = "/opt/jarswaf/logs/jarswaf.log"
max_log_size_mb = 50
max_log_files = 5
blocklist_path = "/opt/jarswaf/blocklist.json"
db_path = "/opt/jarswaf/logs/jarswaf.db"

[[vhosts]]
name = "default"
hosts = ["*"]
backend = "http://localhost:3000"
rules = ["SQLI-*", "XSS-*", "LFI-*", "BOT-*"]
TOML
        [[ -n "$controller_url" ]] && echo -e "\n[controller]\nurl = \"${controller_url}\"\npush_interval = 30" | sudo tee -a "$CONFIG" > /dev/null
        echo -e "${GREEN}✅ Config created${NC}"
    fi

    echo -e "${CYAN}🔧 Installing CLI...${NC}"
    sudo ln -sf "${INSTALL_DIR}/jarswaf" /usr/local/bin/jarswaf 2>/dev/null || \
        sudo cp "${INSTALL_DIR}/jarswaf" /usr/local/bin/jarswaf 2>/dev/null || true
    sudo chmod 755 /usr/local/bin/jarswaf 2>/dev/null || true
    echo -e "${GREEN}✅ CLI installed${NC}"

    echo -e "${GREEN}${BOLD}✅ jarsWAF ${latest} installed!${NC}"
    echo -e "  ${CYAN}▶  Run: sudo jarswaf start${NC}"
}

cmd_uninstall() {
    echo -e "${RED}${BOLD}⚠️  This will remove ALL jarsWAF files!${NC}"
    echo -n "Continue? (y/N): "
    read -r confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && echo "Aborted." && exit 0
    require_root
    kill_all_agents 2>/dev/null || true
    sleep 1
    sudo rm -rf "${INSTALL_DIR}" /usr/local/bin/jarswaf /etc/systemd/system/jarswaf.service
    echo -e "${GREEN}✅ jarsWAF uninstalled${NC}"
}

# ── Main ──
[[ $# -eq 0 ]] && usage && exit 0

case "${1:-help}" in
    start)      cmd_start ;;
    stop)       cmd_stop ;;
    restart)    cmd_restart ;;
    status)     cmd_status ;;
    config)     shift; cmd_config "$@" ;;
    logs)       shift; cmd_logs "$@" ;;
    install)    shift; cmd_install "$@" ;;
    uninstall)  cmd_uninstall ;;
    version)
        [[ -x "$BINARY" ]] && echo "jarsWAF Agent - $(file "$BINARY" | grep -oP 'BuildID\[sha1\]=\K\w+' | head -1)"
        echo "CLI v1.0.0"
        ;;
    help|--help|-h) usage ;;
    *) echo -e "${RED}Unknown: jarswaf ${1}${NC}" >&2; echo "Run 'jarswaf help' for usage" >&2; exit 1 ;;
esac
