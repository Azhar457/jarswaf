#!/bin/bash
set -uo pipefail
# ================================================================
#  jarsWAF — Zero-Shot Installer (Binary Download)
# ================================================================
#  Usage:
#    sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Azhar457/jarswaf/main/install.sh)"
#
#  What this does:
#    1. Detects OS/arch
#    2. Downloads latest release tarball (agent + controller + jarswaf CLI)
#    3. Installs to /opt/jarswaf/
#    4. Creates default config
#    5. Installs CLI wrapper to /usr/local/bin/jarswaf
#    6. Starts agent via systemd (optional)
#
#  No Docker needed. No Rust toolchain. Just curl + binary.
# ================================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── Config ───────────────────────────────────────────────────────
REPO="Azhar457/jarswaf"
INSTALL_DIR="/opt/jarswaf"
CLI_LINK="/usr/local/bin/jarswaf"

# ── Sanity Check ─────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}${BOLD}Error:${NC} This script must be run as root (use sudo)."
   exit 1
fi

if ! command -v curl &>/dev/null; then
    echo -e "${CYAN}📦 Installing curl...${NC}"
    apt-get update -qq && apt-get install -y -qq curl 2>/dev/null || yum install -y -q curl 2>/dev/null || {
        echo -e "${RED}❌ curl required. Install it manually.${NC}"; exit 1
    }
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

# ── Fetch Latest Release ─────────────────────────────────────────
echo -e "${CYAN}${BOLD}🔍 Fetching latest release...${NC}"
LATEST=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$LATEST" ]; then
    echo -e "${YELLOW}⚠️  Using default: v0.2.2${NC}"
    LATEST="v0.2.2"
fi
echo -e "${GREEN}✅ Latest release: ${BOLD}${LATEST}${NC}"

# ── Download & Extract ───────────────────────────────────────────
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/jarswaf-${LATEST#v}-musl.tar.gz"
TMP_TAR="/tmp/jarswaf-linux-${ARCH}.tar.gz"

echo -e "${CYAN}${BOLD}⬇️  Downloading ${LATEST} (linux-${ARCH})...${NC}"
curl --fail --retry 3 -fsSL -o "$TMP_TAR" "$DOWNLOAD_URL"

# Verify integrity if a checksum is published alongside the release.
# The release workflow emits jarswaf-${LATEST#v}-musl.tar.gz.sha256 in the same directory.
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
if curl --fail --retry 2 -fsSL -o /tmp/jarswaf.tar.gz.sha256 "$CHECKSUM_URL" 2>/dev/null; then
    if command -v sha256sum &>/dev/null; then
        echo -e "${CYAN}🔐 Verifying checksum...${NC}"
        ( cd /tmp && sha256sum -c /tmp/jarswaf.tar.gz.sha256 2>/dev/null >/dev/null ) \
            || { echo -e "${RED}❌ Checksum verification failed — possible corruption or tampering.${NC}"; exit 1; }
    else
        echo -e "${YELLOW}⚠️  sha256sum not found — skipped checksum verification.${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  No checksum published for ${LATEST} — verify manually if this concerns you.${NC}"
fi

echo -e "${CYAN}${BOLD}📦 Extracting...${NC}"
mkdir -p "$INSTALL_DIR"
tar -xzf "$TMP_TAR" -C "$INSTALL_DIR"
chmod 755 "${INSTALL_DIR}/agent" "${INSTALL_DIR}/jarswaf" 2>/dev/null
rm -f "$TMP_TAR"

# ── Install CLI Wrapper ──────────────────────────────────────────
echo -e "${CYAN}${BOLD}🔧 Installing CLI: ${CLI_LINK}${NC}"
ln -sf "${INSTALL_DIR}/jarswaf" "${CLI_LINK}"
chmod 755 "${CLI_LINK}"

# ── Create Default Config ────────────────────────────────────────
if [ ! -f "${INSTALL_DIR}/config.toml" ]; then
    echo -e "${CYAN}${BOLD}⚙️  Creating default config...${NC}"

    # Try download from repo, fallback to inline
    if ! curl --fail -fsSL -o "${INSTALL_DIR}/config.toml" \
        "https://raw.githubusercontent.com/${REPO}/main/config.standalone.toml" 2>/dev/null; then
        cat > "${INSTALL_DIR}/config.toml" << 'TOML'
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
backend = "http://localhost:3000"
rules = ["SQLI-*", "XSS-*", "LFI-*", "BOT-*"]
TOML
    fi

    echo -e "${GREEN}✅ Config created${NC}"
fi

# ── Create Systemd Service ───────────────────────────────────────
echo -e "${CYAN}${BOLD}🚀 Installing systemd service...${NC}"

# Run as a dedicated non-root system user. The WAF has no need for root; port 80/443
# binding is granted via AmbientCapabilities=CAP_NET_BIND_SERVICE. `ponytail:` if you reuse
# ports <1024 and the kernel ignores ambient caps on some distros, fall back to setcap on
# the binary (`setcap 'cap_net_bind_service=+ep' ${INSTALL_DIR}/controller`).
if ! id -u jarswaf &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin jarswaf 2>/dev/null || true
fi
chown -R jarswaf:jarswaf "${INSTALL_DIR}" 2>/dev/null || true

cat > "/etc/systemd/system/jarswaf.service" << SERVICE
[Unit]
Description=jarsWAF — Web Application Firewall
After=network.target

[Service]
Type=simple
User=jarswaf
Group=jarswaf
ExecStart=${INSTALL_DIR}/controller --port 8080 --config ${INSTALL_DIR}/config.toml
WorkingDirectory=${INSTALL_DIR}
Restart=always
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable jarswaf 2>/dev/null || true

# ── Ask to Start ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}🎯 jarsWAF ${LATEST} installed!${NC}"
echo -e "  ${CYAN}📂 Binary:${NC}    ${INSTALL_DIR}/agent"
echo -e "  ${CYAN}🛠️  CLI:${NC}      ${CLI_LINK} (or: jarswaf)"
echo -e "  ${CYAN}⚙️  Config:${NC}    ${INSTALL_DIR}/config.toml"
echo ""
answer="y"
if [ -t 0 ]; then
    echo -ne "${BOLD}▶  Start jarsWAF now? (Y/n): ${NC}"
    read -r answer || answer="y"
fi

if [[ "$answer" != "n" && "$answer" != "N" ]]; then
    systemctl start jarswaf 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet jarswaf 2>/dev/null; then
        echo -e "${GREEN}${BOLD}✅ jarsWAF is running!${NC}"
    else
        # Fallback: direct start (Controller + Agent)
        mkdir -p "${INSTALL_DIR}/logs"
        nohup "${INSTALL_DIR}/controller" --port 8080 --config "${INSTALL_DIR}/config.toml" > "${INSTALL_DIR}/controller.log" 2>&1 &
        nohup "${INSTALL_DIR}/agent" --config "${INSTALL_DIR}/config.toml" -u "http://localhost:8080" > "${INSTALL_DIR}/agent.log" 2>&1 &
        echo -e "${YELLOW}⚠️  Started via background nohup processes (Controller & Agent)${NC}"
    fi
else
    echo -e "${CYAN}→ Start manually: sudo jarswaf start${NC}"
fi
