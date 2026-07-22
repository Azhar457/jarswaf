#!/bin/bash
# ================================================================
#  jarsWAF — Zero-Shot Installer (Binary Download)
# ================================================================
#  Usage:
#    bash -c "$(curl -fsSLk https://raw.githubusercontent.com/Azhar457/jarswaf/main/install.sh)"
#
#  What this does:
#    1. Detects OS/arch
#    2. Downloads the latest jarsWAF release binary
#    3. Creates /opt/jarswaf with config, certs, and service file
#    4. Starts jarsWAF via systemd (or background process)
#
#  No Docker needed. No Rust toolchain. Just curl + binary.
# ================================================================

set -e

# ── Colors ───────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Config ───────────────────────────────────────────────────────
REPO="Azhar457/jarswaf"
INSTALL_DIR="/opt/jarswaf"
BINARY_NAME="agent"
SERVICE_NAME="jarswaf"
CONFIG_URL="https://raw.githubusercontent.com/${REPO}/main/config.standalone.toml"

# ── Sanity Check ─────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}${BOLD}Error:${NC} This script must be run as root (use sudo)."
   exit 1
fi

if ! command -v curl &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq curl || yum install -y -q curl
fi

# ── Detect Arch ──────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    *)
        echo -e "${RED}${BOLD}Error:${NC} Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# ── Fetch Latest Release Info ────────────────────────────────────
echo -e "${CYAN}${BOLD}🔍 Fetching latest release...${NC}"
LATEST=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)

if [ -z "$LATEST" ]; then
    echo -e "${YELLOW}⚠️  Could not fetch latest release tag. Using default: v0.2.2${NC}"
    LATEST="v0.2.2"
fi

echo -e "${GREEN}✅ Latest release: ${BOLD}${LATEST}${NC}"

# ── Download Binary ──────────────────────────────────────────────
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/jarswaf-v${LATEST#v}-musl.tar.gz"
TMP_TAR="/tmp/jarswaf-linux-${ARCH}.tar.gz"

echo -e "${CYAN}${BOLD}⬇️  Downloading jarsWAF ${LATEST} (linux-${ARCH})...${NC}"
curl -fsSLk -o "$TMP_TAR" "$DOWNLOAD_URL"

# ── Verify & Extract ─────────────────────────────────────────────
echo -e "${CYAN}${BOLD}📦 Extracting...${NC}"

# Create install directory
mkdir -p "$INSTALL_DIR"

# Extract binary
tar -xzf "$TMP_TAR" -C "$INSTALL_DIR" 2>/dev/null || {
    # If tar.gz extraction fails, try direct binary download
    echo -e "${YELLOW}⚠️  Binary archive extraction failed, trying direct binary...${NC}"
    curl -fsSLk -o "${INSTALL_DIR}/${BINARY_NAME}" \
        "https://github.com/${REPO}/releases/download/${LATEST}/jarswaf-linux-${ARCH}"
}

chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
rm -f "$TMP_TAR"

# ── Create Default Config ────────────────────────────────────────
if [ ! -f "${INSTALL_DIR}/config.toml" ]; then
    echo -e "${CYAN}${BOLD}⚙️  Creating default config...${NC}"

    # Ask for Controller URL (or leave empty for standalone)
    read -r -p "Enter Controller URL (press Enter for standalone mode): " CONTROLLER_URL

    # Download config template from repo
    if curl -fsSLk -o "${INSTALL_DIR}/config.toml" "$CONFIG_URL" 2>/dev/null; then
        :  # config downloaded successfully
    else
        cat > "${INSTALL_DIR}/config.toml" << 'CONFIGEOF'
certificates = []
allowlists = []
blacklists = []

[global]
port_http = 8080
port_https = 8443
max_body_size = 10485760
default_rate_limit = 600
log_dir = "/opt/jarswaf/logs"
log_level = "info"
admin_token = "change-me"
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
backend = "http://127.0.0.1:3000"
rules = []
CONFIGEOF

    # If controller URL provided, add it
    if [ -n "$CONTROLLER_URL" ]; then
        echo -e "\n[controller]\nurl = \"${CONTROLLER_URL}\"\npush_interval = 30" >> "${INSTALL_DIR}/config.toml"
        echo -e "${GREEN}✅ Agent will report to Controller: ${CONTROLLER_URL}${NC}"
    fi
fi

# ── Create Systemd Service ───────────────────────────────────────
echo -e "${CYAN}${BOLD}🚀 Installing systemd service...${NC}"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" << SERVICE
[Unit]
Description=jarsWAF — Web Application Firewall
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME} --config ${INSTALL_DIR}/config.toml
WorkingDirectory=${INSTALL_DIR}
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl start "${SERVICE_NAME}"

# ── Verify ───────────────────────────────────────────────────────
sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo -e "${GREEN}${BOLD}✅ jarsWAF is running!${NC}"
    echo -e "${GREEN}📋 Service: ${SERVICE_NAME}"
    echo -e "${GREEN}📂 Install: ${INSTALL_DIR}"
    echo -e "${GREEN}🔧 Config:  ${INSTALL_DIR}/config.toml"
    echo -e "${GREEN}📝 Log:     $(systemctl status ${SERVICE_NAME} | grep -oP '\/\S+\.log')"
else
    echo -e "${RED}${BOLD}❌ jarsWAF failed to start!${NC}"
    echo -e "${YELLOW}Check logs: journalctl -u ${SERVICE_NAME} --no-pager -n 50${NC}"
fi
