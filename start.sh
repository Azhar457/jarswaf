#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BLUE}${BOLD}===================================================${NC}"
echo -e "${CYAN}${BOLD}  🛡️  jarsWAF Interactive Development Launcher  🛡️${NC}"
echo -e "${BLUE}${BOLD}===================================================${NC}"
echo

# 1. Interactive Inputs
read -p "$(echo -e "${BOLD}Masukkan Port Controller (API/Dashboard) [Default: 8080]: ${NC}")" CTRL_PORT
CTRL_PORT=${CTRL_PORT:-8080}

read -p "$(echo -e "${BOLD}Masukkan Port Agent WAF Proxy [Default: 8000]: ${NC}")" AGENT_PORT
AGENT_PORT=${AGENT_PORT:-8000}

read -p "$(echo -e "${BOLD}Masukkan Target Backend (IP:Port) [Default: 127.0.0.1:8081]: ${NC}")" BACKEND_TARGET
BACKEND_TARGET=${BACKEND_TARGET:-127.0.0.1:8081}

echo -e "\n${BLUE}[INFO] Menyiapkan konfigurasi...${NC}"

# Check for config
CONFIG="config.standalone.toml"
[ -f "$CONFIG" ] || { echo -e "${RED}Missing $CONFIG${NC}"; exit 1; }

# 2. Run Python inline helper to rewrite configuration files
TOKEN=$(python3 -c '
import sys, re, uuid
agent_port = sys.argv[1]
backend_target = sys.argv[2]
ctrl_port = sys.argv[3]

with open("config.standalone.toml", "r") as f:
    content = f.read()

content = re.sub(r"port_http\s*=\s*\d+", f"port_http = {agent_port}", content)
content = re.sub(r"backend\s*=\s*\"[^\"]+\"", f"backend = \"{backend_target}\"", content)

# Check and generate admin token if needed
token_match = re.search(r"admin_token\s*=\s*\"([^\"]*)\"", content)
token = token_match.group(1).strip() if token_match else ""
if not token:
    token = uuid.uuid4().hex
    if "admin_token" in content:
        content = re.sub(r"admin_token\s*=\s*\"[^\"]*\"", f"admin_token = \"{token}\"", content)
    else:
        content = content.replace("[global]\n", f"[global]\nadmin_token = \"{token}\"\n")

with open("config.standalone.toml", "w") as f:
    f.write(content)

# Update Vite configurations
for fn in ["dashboard/vite.config.ts", "dashboard/vite.config.js"]:
    try:
        with open(fn, "r") as f:
            c = f.read()
        c = re.sub(r"target:\s*\"http://localhost:\d+\"", f"target: \"http://localhost:{ctrl_port}\"", c)
        c = re.sub(r"target:\s*\"ws://localhost:\d+\"", f"target: \"ws://localhost:{ctrl_port}\"", c)
        with open(fn, "w") as f:
            f.write(c)
    except FileNotFoundError:
        pass

print(token)
' "$AGENT_PORT" "$BACKEND_TARGET" "$CTRL_PORT")

PID_CNTR=0
PID_AGENT=0
PID_VITE=0

cleanup() {
    echo
    echo -e "${YELLOW}Stopping jarsWAF processes...${NC}"
    if [ "$PID_CNTR" -ne 0 ]; then kill "$PID_CNTR" 2>/dev/null || true; fi
    if [ "$PID_AGENT" -ne 0 ]; then
        if [ "$AGENT_PORT" -lt 1024 ]; then
            sudo kill "$PID_AGENT" 2>/dev/null || true
        else
            kill "$PID_AGENT" 2>/dev/null || true
        fi
    fi
    if [ "$PID_VITE" -ne 0 ]; then kill "$PID_VITE" 2>/dev/null || true; fi
    exit
}
trap cleanup SIGINT SIGTERM

echo -e "${GREEN}[ OK ] Konfigurasi diperbarui.${NC}"
echo -e "${MAGENTA}Admin Token: ${YELLOW}$TOKEN${NC}\n"

echo -e "${BLUE}Compiling jarsWAF binaries...${NC}"
cargo build --bin controller --bin agent

# Check if port is privileged
SUDO_CMD=""
if [ "$AGENT_PORT" -lt 1024 ]; then
    echo -e "${YELLOW}[WARN] Port Agent $AGENT_PORT < 1024. Memerlukan hak akses administrator (sudo) untuk menjalankan Agent.${NC}"
    SUDO_CMD="sudo"
fi

echo -e "${BLUE}Step 1: Starting Controller (API server) on port $CTRL_PORT...${NC}"
./target/debug/controller --port "$CTRL_PORT" --config "$CONFIG" &
PID_CNTR=$!

sleep 3

echo -e "\n${BLUE}Step 2: Starting Agent (WAF proxy) on port $AGENT_PORT...${NC}"
$SUDO_CMD ./target/debug/agent -c "$CONFIG" -u "http://localhost:$CTRL_PORT" -t "$TOKEN" &
PID_AGENT=$!

sleep 2

echo -e "\n${BLUE}Step 3: Starting Dashboard (Vite dev server)...${NC}"
cd dashboard && npm run dev &
PID_VITE=$!
cd "$SCRIPT_DIR"

echo
echo -e "${GREEN}${BOLD}===================================================${NC}"
echo -e "${GREEN}${BOLD}  jarsWAF Berhasil Dijalankan!${NC}"
echo -e "  Dashboard UI   → ${BOLD}http://localhost:5173/${NC}"
echo -e "  Controller API → ${BOLD}http://localhost:$CTRL_PORT/${NC}"
echo -e "  WAF Agent Port → ${BOLD}http://localhost:$AGENT_PORT/${NC} (Bypass ke WAF)"
echo -e "  Backend Target → ${BOLD}http://$BACKEND_TARGET/${NC}"
echo -e "${YELLOW}  Tekan Ctrl+C untuk menghentikan semua proses.${NC}"
echo -e "${GREEN}${BOLD}===================================================${NC}"

wait
