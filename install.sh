#!/bin/bash
set -uo pipefail
# ================================================================
#  jarsWAF — SafeLine-Style Interactive Zero-Shot Installer
# ================================================================
#  Usage:
#    sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Azhar457/jarswaf/main/install.sh)"
#
#  Non-interactive CLI Options:
#    sudo ./install.sh --action install --mode standalone
#    sudo ./install.sh --action upgrade
#    sudo ./install.sh --action reset-password
#    sudo ./install.sh --action uninstall
# ================================================================

set -euo pipefail

# ── Colors & Styles ──────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── Config Defaults ──────────────────────────────────────────────
REPO="Azhar457/jarswaf"
INSTALL_DIR="/opt/jarswaf"
CLI_LINK="/usr/local/bin/jarswaf"
ACTION=""
MODE=""
CONTROLLER_URL="http://localhost:8080"
AGENT_TOKEN=""

# Parse CLI Flags
while [[ $# -gt 0 ]]; do
  case $1 in
    --action|-a)
      ACTION="$2"; shift 2 ;;
    --mode|-m)
      MODE="$2"; shift 2 ;;
    --controller-url|-u)
      CONTROLLER_URL="$2"; shift 2 ;;
    --token|-t)
      AGENT_TOKEN="$2"; shift 2 ;;
    *)
      shift ;;
  esac
done

# ── Sanity Check ─────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}${BOLD}Error:${NC} Script ini harus dijalankan sebagai root (gunakan sudo)."
   exit 1
fi

if ! command -v curl &>/dev/null; then
    echo -e "${CYAN}📦 Memasang curl...${NC}"
    apt-get update -qq && apt-get install -y -qq curl 2>/dev/null || yum install -y -q curl 2>/dev/null || {
        echo -e "${RED}❌ curl dibutuhkan. Silakan pasang secara manual.${NC}"; exit 1
    }
fi

# ── Detect Arch ──────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    *)
        echo -e "${RED}${BOLD}Error:${NC} Arsitektur tidak didukung: $ARCH"
        exit 1
        ;;
esac

# ── Interactive Arrow-Key Menu Selector ──────────────────────────
old_stty=""

cleanup_menu() {
    if [ -n "${old_stty:-}" ]; then
        stty "${old_stty}" 2>/dev/null || true
    fi
    echo -ne "\033[?25h" # Restore cursor
}

# Usage: select_option "OUT_VAR_NAME" "Header Title" "Option 1" "Option 2" ...
select_option() {
    local out_var="$1"
    local title="$2"
    shift 2
    local options=("$@")
    local selected=0
    local key=""

    # Fallback for non-interactive environment (e.g. CI/pipes)
    if [ ! -t 0 ]; then
        eval "$out_var=\"0\""
        return
    fi

    # Save terminal state & hide cursor
    old_stty=$(stty -g 2>/dev/null || echo "")
    stty -echo -icanon min 1 time 0 2>/dev/null || true
    echo -ne "\033[?25l"

    trap cleanup_menu EXIT INT TERM

    print_menu() {
        echo -e "${BOLD}${title}${NC}"
        echo -e "${DIM}(Gunakan Panah ⬆️ / ⬇️ / [W][S] / [K][J] & Tekan ENTER)${NC}\n"
        for i in "${!options[@]}"; do
            if [ "$i" -eq "$selected" ]; then
                echo -e "  ${GREEN}${BOLD}➔ \033[7m ${options[$i]} \033[0m${NC}"
            else
                echo -e "     ${options[$i]}"
            fi
        done
    }

    print_menu

    while true; do
        key=""
        IFS= read -rsn1 key || true

        if [ "$key" == $'\x1b' ]; then
            local esc_rest=""
            IFS= read -rsn2 -t 0.1 esc_rest || true
            case "$esc_rest" in
                "[A"|"OA") # Up Arrow
                    selected=$(( (selected - 1 + ${#options[@]}) % ${#options[@]} ))
                    ;;
                "[B"|"OB") # Down Arrow
                    selected=$(( (selected + 1) % ${#options[@]} ))
                    ;;
            esac
        elif [ "$key" == "k" ] || [ "$key" == "K" ] || [ "$key" == "w" ] || [ "$key" == "W" ]; then
            selected=$(( (selected - 1 + ${#options[@]}) % ${#options[@]} ))
        elif [ "$key" == "j" ] || [ "$key" == "J" ] || [ "$key" == "s" ] || [ "$key" == "S" ]; then
            selected=$(( (selected + 1) % ${#options[@]} ))
        elif [ "$key" == "" ] || [ "$key" == $'\n' ] || [ "$key" == $'\r' ]; then
            # Enter Key
            break
        fi

        # Clear menu lines and redraw
        local lines_to_clear=$((${#options[@]} + 3))
        echo -ne "\033[${lines_to_clear}A"
        print_menu
    done

    cleanup_menu
    trap - EXIT INT TERM
    echo ""

    eval "$out_var=\"$selected\""
}

# ── Interactive Menu Loop ────────────────────────────────────────
while true; do
    ACTION=""
    MODE=""

    # Check Installation Status
    IS_INSTALLED=false
    if [ -d "$INSTALL_DIR" ] || [ -f "/etc/systemd/system/jarswaf.service" ]; then
        IS_INSTALLED=true
    fi

    # Main Banner
    clear 2>/dev/null || true
    echo -e "${CYAN}${BOLD}"
    echo "==============================================================="
    echo "🛡️  jarsWAF ZERO-SHOT INSTALLER & MANAGEMENT UTILITY"
    echo "==============================================================="
    if [ "$IS_INSTALLED" = true ]; then
        echo -e "  ${BOLD}Status Sistem:${NC} ${GREEN}${BOLD}● TERPASANG (${INSTALL_DIR})${NC}"
    else
        echo -e "  ${BOLD}Status Sistem:${NC} ${YELLOW}${BOLD}○ BELUM TERPASANG${NC}"
    fi
    echo -e "${CYAN}${BOLD}===============================================================${NC}\n"

    # Action Selection Menu
    if [ -t 0 ]; then
        ACTION_CHOICE=0
        select_option ACTION_CHOICE "Pilih Aksi yang Ingin Dilakukan:" \
            "🚀 INSTALL / RECONFIGURE (Pasang / Konfigurasi Ulang jarsWAF)" \
            "🔄 UPGRADE (Perbarui Biner ke Versi Rilis Terbaru)" \
            "🔐 RESET PASSWORD (Reset Admin Password ke Baru)" \
            "🗑️  UNINSTALL (Hentikan Service & Hapus Total jarsWAF)" \
            "❌ EXIT (Keluar)"

        case "$ACTION_CHOICE" in
            0) ACTION="install" ;;
            1) ACTION="upgrade" ;;
            2) ACTION="reset-password" ;;
            3) ACTION="uninstall" ;;
            4) echo -e "${CYAN}Dibatalkan.${NC}"; exit 0 ;;
            *) ACTION="install" ;;
        esac
    else
        ACTION="install"
    fi

    # Handle Action: UNINSTALL
    if [ "$ACTION" == "uninstall" ]; then
        if [ "$IS_INSTALLED" = false ]; then
            echo -e "${YELLOW}${BOLD}⚠️  jarsWAF belum terpasang atau sudah di-uninstall sebelumnya.${NC}"
            echo -e "${DIM}Direktori ${INSTALL_DIR} dan service systemd tidak ditemukan.${NC}\n"
            exit 0
        fi

        echo -e "${YELLOW}${BOLD}⚠️  UNINSTALLATION JARSWAF${NC}"
        echo -e "${RED}Ini akan menghentikan service, menghapus biner, dan membersihkan ${INSTALL_DIR}.${NC}\n"
        
        if [ -t 0 ]; then
            read -p "$(echo -e "${BOLD}Apakah Anda yakin ingin melanjutkan? (y/N): ${NC}")" CONFIRM || CONFIRM="n"
            if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
                echo -e "${CYAN}Uninstall dibatalkan.${NC}"; exit 0
            fi
        fi

        echo -e "${CYAN}🛑 Menghentikan service systemd & proses latar belakang...${NC}"
        systemctl stop jarswaf 2>/dev/null || true
        systemctl disable jarswaf 2>/dev/null || true
        rm -f "/etc/systemd/system/jarswaf.service"
        systemctl daemon-reload 2>/dev/null || true

        pkill -9 -f "target/debug/[a]gent" 2>/dev/null || true
        pkill -9 -f "target/release/[a]gent" 2>/dev/null || true
        pkill -9 -f "target/debug/[c]ontroller" 2>/dev/null || true
        pkill -9 -f "target/release/[c]ontroller" 2>/dev/null || true
        pkill -9 -f "/opt/jarswaf/[c]ontroller" 2>/dev/null || true
        pkill -9 -f "/opt/jarswaf/[a]gent" 2>/dev/null || true

        echo -e "${CYAN}🗑️  Menghapus biner & direktori instalasi...${NC}"
        rm -f "$CLI_LINK"
        rm -rf "$INSTALL_DIR"

        echo -e "${GREEN}${BOLD}✅ jarsWAF berhasil di-uninstall dari sistem.${NC}"
        exit 0
    fi

    # Handle Action: RESET PASSWORD
    if [ "$ACTION" == "reset-password" ]; then
        if [ "$IS_INSTALLED" = false ] || [ ! -f "${INSTALL_DIR}/config.toml" ]; then
            echo -e "${RED}❌ Aksi Gagal: jarsWAF belum terpasang di sistem ini.${NC}"
            echo -e "   Silakan pilih opsi '🚀 INSTALL / RECONFIGURE' terlebih dahulu.\n"
            exit 1
        fi

        NEW_PASS=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)
        if [ -z "$NEW_PASS" ]; then
            NEW_PASS=$(date +%s%N | sha256sum | head -c 20)
        fi
        echo -e "${CYAN}🔐 Mengatur ulang Admin Password...${NC}"

        # Replace admin_token and set must_change_password = true
        sed -i -E 's/^\s*admin_token\s*=.*/admin_token = "'"${NEW_PASS}"'"/' "${INSTALL_DIR}/config.toml"
        if ! grep -q "must_change_password" "${INSTALL_DIR}/config.toml"; then
            echo "must_change_password = true" >> "${INSTALL_DIR}/config.toml"
        else
            sed -i -E 's/^\s*must_change_password\s*=.*/must_change_password = true/' "${INSTALL_DIR}/config.toml"
        fi

        systemctl restart jarswaf 2>/dev/null || true

        echo -e "\n${GREEN}${BOLD}===============================================================${NC}"
        echo -e "${GREEN}${BOLD}✅ Admin Password Berhasil Di-reset!${NC}"
        echo -e "${GREEN}${BOLD}===============================================================${NC}"
        echo -e "  ${BOLD}👤 Username      :${NC} ${YELLOW}admin${NC}"
        echo -e "  ${BOLD}🔑 Password Baru :${NC} ${MAGENTA}${NEW_PASS}${NC}"
        echo -e "  ${YELLOW}⚠️  Silakan login di Dashboard GUI dan ubah password saat diminta.${NC}"
        echo -e "${GREEN}${BOLD}===============================================================${NC}\n"
        exit 0
    fi

    # Handle Action: UPGRADE
    if [ "$ACTION" == "upgrade" ]; then
        if [ "$IS_INSTALLED" = false ]; then
            echo -e "${RED}❌ Aksi Gagal: jarsWAF belum terpasang di sistem ini.${NC}"
            echo -e "   Silakan pilih opsi '🚀 INSTALL / RECONFIGURE' terlebih dahulu.\n"
            exit 1
        fi
        echo -e "${CYAN}${BOLD}🔄 Memperbarui biner & UI assets jarsWAF (konfigurasi dipertahankan)...${NC}\n"
    fi

    # Mode Selection Menu (for Install)
    if [ "$ACTION" == "install" ]; then
        if [ -t 0 ]; then
            MODE_CHOICE=0
            select_option MODE_CHOICE "Pilih Mode Deployment jarsWAF:" \
                "🛡️  Standalone Mode (Rekomendasi — Controller + Dashboard + Embedded Agent)" \
                "🌐 Controller Only Mode (Server Manajemen Pusat & Dashboard Analytics)" \
                "📡 Agent Only Mode (Node WAF Proxy Terpisah ke Central Controller)" \
                "⬅️  KEMBALI (Kembali ke Menu Utama)"

            case "$MODE_CHOICE" in
                0) MODE="standalone" ;;
                1) MODE="controller" ;;
                2) MODE="agent" ;;
                3) continue ;; # Go back to main menu loop
                *) MODE="standalone" ;;
            esac
        else
            MODE="standalone"
        fi
    fi

    break # Proceed with selected action!
done

if [ -z "$MODE" ]; then
    MODE="standalone"
fi

echo -e "${GREEN}✅ Mode Terpilih: ${BOLD}${MODE^^}${NC}\n"

# ── Fetch Latest Release ─────────────────────────────────────────
echo -e "${CYAN}${BOLD}🔍 Memeriksa rilis terbaru dari GitHub (${REPO})...${NC}"
LATEST=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4 || echo "v0.2.2")
if [ -z "$LATEST" ]; then
    LATEST="v0.2.2"
fi
echo -e "${GREEN}✅ Versi Rilis: ${BOLD}${LATEST}${NC}"

# ── Download & Extract with 3-Stage Fallback ──────────────────────
mkdir -p "$INSTALL_DIR"
BINARY_OBTAINED=false
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/jarswaf-${LATEST#v}-musl.tar.gz"
TMP_TAR="/tmp/jarswaf-linux-${ARCH}.tar.gz"

echo -e "${CYAN}${BOLD}⬇️  Downloading ${LATEST} (linux-${ARCH})...${NC}"
if curl --fail --retry 3 -fsSL -o "$TMP_TAR" "$DOWNLOAD_URL" 2>/dev/null; then
    # Verify integrity if a checksum is published alongside the release.
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
    echo -e "${CYAN}${BOLD}📦 Ekstraksi biner ke ${INSTALL_DIR}...${NC}"
    tar -xzf "$TMP_TAR" -C "$INSTALL_DIR" 2>/dev/null || true
    chmod 755 "${INSTALL_DIR}/agent" "${INSTALL_DIR}/controller" "${INSTALL_DIR}/jarswaf" 2>/dev/null || true
    rm -f "$TMP_TAR"
    BINARY_OBTAINED=true
else
    echo -e "${YELLOW}⚠️  Paket tarball ${LATEST} belum dipublikasikan di GitHub Releases.${NC}"
    DIRECT_URL="https://github.com/${REPO}/releases/download/${LATEST}/jarswaf-linux-amd64-musl"
    if curl -fsSLk -o "${INSTALL_DIR}/jarswaf" "$DIRECT_URL" 2>/dev/null; then
        chmod 755 "${INSTALL_DIR}/jarswaf"
        BINARY_OBTAINED=true
    fi
fi

# Stage 2: Fallback to Local Project Workspace Binaries
if [ "$BINARY_OBTAINED" = false ]; then
    echo -e "${CYAN}${BOLD}🔍 Memeriksa biner lokal dari direktori project...${NC}"
    LOCAL_SRC=""
    if [ -f "./target/release/controller" ]; then
        LOCAL_SRC="./target/release"
    elif [ -f "./target/debug/controller" ]; then
        LOCAL_SRC="./target/debug"
    elif [ -f "./target/x86_64-unknown-linux-musl/release/controller" ]; then
        LOCAL_SRC="./target/x86_64-unknown-linux-musl/release"
    fi

    if [ -n "$LOCAL_SRC" ]; then
        echo -e "${GREEN}${BOLD}✅ Biner lokal ditemukan di ${LOCAL_SRC}. Memasang biner...${NC}"
        cp "${LOCAL_SRC}/controller" "${INSTALL_DIR}/controller" 2>/dev/null || true
        cp "${LOCAL_SRC}/agent" "${INSTALL_DIR}/agent" 2>/dev/null || true
        cp "${LOCAL_SRC}/jarswaf" "${INSTALL_DIR}/jarswaf" 2>/dev/null || true
        chmod 755 "${INSTALL_DIR}/agent" "${INSTALL_DIR}/controller" "${INSTALL_DIR}/jarswaf" 2>/dev/null || true
        
        if [ -d "./dashboard/dist" ]; then
            echo -e "${CYAN}${BOLD}🎨 Memasang Dashboard UI assets ke ${INSTALL_DIR}/dashboard/dist...${NC}"
            mkdir -p "${INSTALL_DIR}/dashboard"
            cp -r ./dashboard/dist "${INSTALL_DIR}/dashboard/dist" 2>/dev/null || true
        fi
        BINARY_OBTAINED=true
    fi
fi

# Stage 3: Fallback to cargo build --release if cargo is present
if [ "$BINARY_OBTAINED" = false ]; then
    if command -v cargo &>/dev/null && [ -f "Cargo.toml" ]; then
        echo -e "${CYAN}${BOLD}🔨 Mengompilasi biner rilis lokal via Cargo...${NC}"
        cargo build --release --workspace
        cp target/release/controller "${INSTALL_DIR}/controller" 2>/dev/null || true
        cp target/release/agent "${INSTALL_DIR}/agent" 2>/dev/null || true
        cp target/release/jarswaf "${INSTALL_DIR}/jarswaf" 2>/dev/null || true
        chmod 755 "${INSTALL_DIR}/agent" "${INSTALL_DIR}/controller" "${INSTALL_DIR}/jarswaf" 2>/dev/null || true

        if [ -d "./dashboard/dist" ]; then
            echo -e "${CYAN}${BOLD}🎨 Memasang Dashboard UI assets ke ${INSTALL_DIR}/dashboard/dist...${NC}"
            mkdir -p "${INSTALL_DIR}/dashboard"
            cp -r ./dashboard/dist "${INSTALL_DIR}/dashboard/dist" 2>/dev/null || true
        fi
        BINARY_OBTAINED=true
    fi
fi

if [ "$BINARY_OBTAINED" = false ]; then
    echo -e "${RED}${BOLD}❌ Gagal mendapatkan biner jarsWAF.${NC}"
    echo -e "   Silakan pastikan rilis GitHub telah di-upload atau jalankan 'cargo build --release' terlebih dahulu."
    exit 1
fi

# ── Install CLI Wrapper ──────────────────────────────────────────
echo -e "${CYAN}${BOLD}🔧 Memasang pertautan CLI: ${CLI_LINK}${NC}"
ln -sf "${INSTALL_DIR}/jarswaf" "${CLI_LINK}" 2>/dev/null || true
chmod 755 "${CLI_LINK}" 2>/dev/null || true

# ── Password Auto-Generation & Config ───────────────────────────
GENERATED_PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)
if [ -z "$GENERATED_PASSWORD" ]; then
    GENERATED_PASSWORD=$(date +%s%N | sha256sum | head -c 20)
fi

if [ ! -f "${INSTALL_DIR}/config.toml" ]; then
    echo -e "${CYAN}${BOLD}⚙️  Creating default config...${NC}"

    # Try download from repo, fallback to inline
    if ! curl --fail -fsSL -o "${INSTALL_DIR}/config.toml" \
        "https://raw.githubusercontent.com/${REPO}/main/config.standalone.toml" 2>/dev/null; then
        cat > "${INSTALL_DIR}/config.toml" << 'TOML'
certificates = []
allowlists = []
blacklists = []
api_schemas = []

[global]
port_http = 8000
port_https = 8443
max_body_size = 10485760
default_rate_limit = 600
log_dir = "./logs"
log_level = "verbose"
mode = "${MODE}"
grpc_token = "[REDACTED-CREDENTIAL]"
admin_token = "${GENERATED_PASSWORD}"
waf_enabled = true
webhooks = []
metrics_push_interval_secs = 60
scoring_mode = "immediate"
anomaly_threshold = 5
ast_learning_enabled = false

[tls]
mode = "disabled"
cert_dir = "./certs"

[logging]
mode = "file"
log_path = "./logs/jarswaf.log"
max_log_size_mb = 50
max_log_files = 5
push_interval_secs = 300
push_batch_size = 100
blocklist_path = "./blocklist.json"
db_path = "./logs/jarswaf.db"

[components]
dashboard = false
clickhouse = false
service_discovery = false
geoip = false

[[vhosts]]
name = "default"
hosts = ["*"]
is_default = true
backend = "http://localhost:3000"
rules = ["SQLI-*", "XSS-*", "LFI-*", "BOT-*"]
TOML
    else
        # We successfully downloaded the template. Replace the placeholder token with the generated password.
        sed -i -E 's/^\s*admin_token\s*=.*/admin_token = "'"${GENERATED_PASSWORD}"'"/' "${INSTALL_DIR}/config.toml"
        # Set must_change_password to true
        if ! grep -q "must_change_password" "${INSTALL_DIR}/config.toml"; then
            echo "must_change_password = true" >> "${INSTALL_DIR}/config.toml"
        else
            sed -i -E 's/^\s*must_change_password\s*=.*/must_change_password = true/' "${INSTALL_DIR}/config.toml"
        fi
    fi
else
    # Config already exists (Upgrade or reconfigure)
    EXISTING_TOKEN=$(grep -E '^\s*admin_token\s*=' "${INSTALL_DIR}/config.toml" | cut -d'"' -f2 || true)
    if [ -n "$EXISTING_TOKEN" ]; then
        GENERATED_PASSWORD="$EXISTING_TOKEN"
    else
        # No token in existing config, write the generated one
        echo "admin_token = \"${GENERATED_PASSWORD}\"" >> "${INSTALL_DIR}/config.toml"
        echo "must_change_password = true" >> "${INSTALL_DIR}/config.toml"
    fi
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

# Stop any existing service and kill stale processes before restart
systemctl stop jarswaf 2>/dev/null || true
pkill -9 -f "${INSTALL_DIR}/[c]ontroller" 2>/dev/null || true
pkill -9 -f "${INSTALL_DIR}/[a]gent" 2>/dev/null || true
sleep 1

case "$MODE" in
    standalone|controller)
        EXEC_CMD="${INSTALL_DIR}/controller --port 9443 --config ${INSTALL_DIR}/config.toml"
        ;;
    agent)
        EXEC_CMD="${INSTALL_DIR}/agent --config ${INSTALL_DIR}/config.toml -u ${CONTROLLER_URL}"
        if [ -n "$AGENT_TOKEN" ]; then
            EXEC_CMD="${EXEC_CMD} -t ${AGENT_TOKEN}"
        fi
        ;;
esac

cat > "/etc/systemd/system/jarswaf.service" << SERVICE
[Unit]
Description=jarsWAF (${MODE^^} Mode) — Web Application Firewall
After=network.target

[Service]
Type=simple
User=jarswaf
Group=jarswaf
ExecStart=${EXEC_CMD}
WorkingDirectory=${INSTALL_DIR}
Restart=always
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload 2>/dev/null || true
systemctl enable jarswaf 2>/dev/null || true
systemctl restart jarswaf 2>/dev/null || true

# ── Banner Final ─────────────────────────────────────────────────
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
echo -e "${GREEN}${BOLD}===============================================================${NC}"
echo -e "${GREEN}${BOLD}🎉 jarsWAF Berhasil Terpasang & Berjalan! (Mode: ${MODE^^})${NC}"
echo -e "${GREEN}${BOLD}===============================================================${NC}"
if [ "$MODE" != "agent" ]; then
    echo -e "  ${BOLD}🌐 Dashboard GUI :${NC} ${CYAN}http://${SERVER_IP}:9443${NC} (atau http://localhost:8080)"
    echo -e "  ${BOLD}👤 Username      :${NC} ${YELLOW}admin${NC}"
    if [ "$ACTION" == "upgrade" ]; then
        echo -e "  ${BOLD}🔑 Password Admin :${NC} ${DIM}(Menggunakan password aktif dari ${INSTALL_DIR}/config.toml)${NC}"
    else
        echo -e "  ${BOLD}🔑 Password Awal :${NC} ${MAGENTA}${GENERATED_PASSWORD}${NC}"
        echo -e "  ${YELLOW}⚠️  Harap login & ganti password saat pertama kali masuk Dashboard.${NC}"
    fi

    CONFIG_HTTP_PORT=$(grep -E '^\s*port_http\s*=' "${INSTALL_DIR}/config.toml" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "80")
    if [ "$CONFIG_HTTP_PORT" == "80" ]; then
        WAF_URL="http://${SERVER_IP}"
    else
        WAF_URL="http://${SERVER_IP}:${CONFIG_HTTP_PORT}"
    fi
    echo -e "  ${BOLD}🛡️  WAF Proxy Port:${NC} ${CYAN}${WAF_URL}${NC}"
else
    echo -e "  ${BOLD}📡 Agent Node    :${NC} Terhubung ke Controller: ${CONTROLLER_URL}"
    echo -e "  ${BOLD}🛡️  WAF Proxy Port:${NC} ${CYAN}${WAF_URL}${NC}"
fi
echo -e "${GREEN}---------------------------------------------------------------${NC}"
echo -e "  ${BOLD}⚙️  File Config  :${NC} ${INSTALL_DIR}/config.toml"
echo -e "  ${BOLD}🛠️  Perintah CLI :${NC} jarswaf status / jarswaf --help"
echo -e "${GREEN}${BOLD}===============================================================${NC}"
echo ""
