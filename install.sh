#!/bin/bash
# ================================================================
#  Aegis WAF — One-Command Installer
# ================================================================
#  Usage:
#    bash -c "$(curl -fsSLk https://raw.githubusercontent.com/Azhar457/aegis-waf/main/install.sh)"
#
#  What this does:
#    1. Checks/installs Docker
#    2. Creates /opt/aegis-waf directory
#    3. Generates Dockerfile, docker-compose.yml, and config.toml
#    4. Asks for your backend app details
#    5. Builds and starts the Aegis WAF Agent container
#
#  No git clone needed. No Rust toolchain needed. Just Docker.
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

# ── Globals ──────────────────────────────────────────────────────
INSTALL_DIR="/opt/aegis-waf"
AEGIS_VERSION="1.0.0"
GITHUB_REPO="https://raw.githubusercontent.com/Azhar457/aegis-waf/main"

# ── Helper Functions ─────────────────────────────────────────────
print_banner() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "    █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗    ██╗ █████╗ ███████╗"
    echo "   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ██║    ██║██╔══██╗██╔════╝"
    echo "   ███████║█████╗  ██║  ███╗██║███████╗    ██║ █╗ ██║███████║█████╗  "
    echo "   ██╔══██║██╔══╝  ██║   ██║██║╚════██║    ██║███╗██║██╔══██║██╔══╝  "
    echo "   ██║  ██║███████╗╚██████╔╝██║███████║    ╚███╔███╔╝██║  ██║██║     "
    echo "   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     "
    echo -e "${NC}"
    echo -e "${DIM}   Web Application Firewall — Lightweight Agent Installer v${AEGIS_VERSION}${NC}"
    echo -e "${DIM}   https://github.com/Azhar457/aegis-waf${NC}"
    echo ""
}

log_info()    { echo -e "  ${BLUE}[INFO]${NC}    $1"; }
log_success() { echo -e "  ${GREEN}[✓]${NC}       $1"; }
log_warn()    { echo -e "  ${YELLOW}[WARN]${NC}    $1"; }
log_error()   { echo -e "  ${RED}[ERROR]${NC}   $1"; }
log_step()    { echo -e "  ${MAGENTA}[STEP $1]${NC}  $2"; }

# ── Pre-flight Checks ───────────────────────────────────────────
preflight() {
    # Must be root or sudo
    if [ "$EUID" -ne 0 ]; then
        log_error "This installer must be run as root or with sudo."
        echo ""
        echo -e "  Run: ${BOLD}sudo bash -c \"\$(curl -fsSLk ${GITHUB_REPO}/install.sh)\"${NC}"
        echo ""
        exit 1
    fi

    # Check OS
    if [ ! -f /etc/os-release ]; then
        log_error "Unsupported OS. This installer requires Linux."
        exit 1
    fi

    source /etc/os-release
    log_info "Detected OS: ${BOLD}${PRETTY_NAME}${NC}"
}

# ── Docker Installation ─────────────────────────────────────────
ensure_docker() {
    if command -v docker &> /dev/null; then
        log_success "Docker is already installed: $(docker --version)"
    else
        log_step "1" "Installing Docker..."
        curl -fsSL https://get.docker.com | sh
        systemctl enable docker && systemctl start docker
        log_success "Docker installed successfully."
    fi

    # Check Docker Compose
    if docker compose version &> /dev/null; then
        log_success "Docker Compose is available."
    else
        log_error "Docker Compose (v2) is required but not found."
        log_info "Try: ${BOLD}apt install docker-compose-plugin${NC}"
        exit 1
    fi
}

# ── Interactive Configuration ────────────────────────────────────
configure_interactively() {
    echo ""
    echo -e "${CYAN}${BOLD}  ── Configuration ──${NC}"
    echo ""

    # Backend host
    read -p "  Your backend app address [127.0.0.1:8000]: " BACKEND_ADDR
    BACKEND_ADDR=${BACKEND_ADDR:-"127.0.0.1:8000"}

    # Domain
    read -p "  Your domain name(s), comma separated [localhost]: " DOMAIN_NAMES
    DOMAIN_NAMES=${DOMAIN_NAMES:-"localhost"}

    # HTTP port
    read -p "  HTTP listen port [80]: " HTTP_PORT
    HTTP_PORT=${HTTP_PORT:-80}

    # HTTPS port
    read -p "  HTTPS listen port [443]: " HTTPS_PORT
    HTTPS_PORT=${HTTPS_PORT:-443}

    # Rate limit
    read -p "  Rate limit (requests per minute) [600]: " RATE_LIMIT
    RATE_LIMIT=${RATE_LIMIT:-600}

    # Remote controller (optional)
    read -p "  Central Controller URL (leave empty for standalone): " CONTROLLER_URL

    # Determine logging mode
    if [ -n "$CONTROLLER_URL" ]; then
        LOG_MODE="remote"
    else
        LOG_MODE="file"
    fi

    echo ""
    echo -e "${CYAN}${BOLD}  ── Summary ──${NC}"
    echo -e "  Backend:      ${BOLD}${BACKEND_ADDR}${NC}"
    echo -e "  Domain(s):    ${BOLD}${DOMAIN_NAMES}${NC}"
    echo -e "  HTTP port:    ${BOLD}${HTTP_PORT}${NC}"
    echo -e "  HTTPS port:   ${BOLD}${HTTPS_PORT}${NC}"
    echo -e "  Rate limit:   ${BOLD}${RATE_LIMIT} req/min${NC}"
    echo -e "  Logging:      ${BOLD}${LOG_MODE}${NC}"
    if [ -n "$CONTROLLER_URL" ]; then
        echo -e "  Controller:   ${BOLD}${CONTROLLER_URL}${NC}"
    fi
    echo ""

    read -p "  Proceed with installation? [Y/n]: " CONFIRM
    CONFIRM=${CONFIRM:-Y}
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        log_warn "Installation cancelled."
        exit 0
    fi
}

# ── Format domain list for TOML ──────────────────────────────────
format_domains_toml() {
    local IFS=','
    local result=""
    for domain in $DOMAIN_NAMES; do
        domain=$(echo "$domain" | xargs) # trim whitespace
        if [ -n "$result" ]; then
            result="${result}, "
        fi
        result="${result}\"${domain}\""
    done
    echo "[$result]"
}

# ── Generate Files ───────────────────────────────────────────────
generate_files() {
    log_step "2" "Creating installation directory: ${INSTALL_DIR}"
    mkdir -p "${INSTALL_DIR}"/{logs,certs,src}
    cd "${INSTALL_DIR}"

    # ── Download source or precompiled binary from GitHub ─────────
    log_step "3" "Checking for precompiled Aegis WAF binary..."
    
    BINARY_URL="https://github.com/Azhar457/aegis-waf/releases/latest/download/aegis-waf-linux-amd64"
    EBPF_URL="https://github.com/Azhar457/aegis-waf/releases/latest/download/aegis-ebpf"
    
    if curl -fsSL -I "$BINARY_URL" >/dev/null 2>&1; then
        log_success "Precompiled binary found! Downloading..."
        curl -fsSL "$BINARY_URL" -o aegis-waf
        chmod +x aegis-waf
        
        # Download eBPF object if available
        if curl -fsSL -I "$EBPF_URL" >/dev/null 2>&1; then
            log_success "Precompiled eBPF binary found! Downloading..."
            curl -fsSL "$EBPF_URL" -o aegis-ebpf
        fi
        
        USE_PRECOMPILED=true
    else
        log_warn "Precompiled binary not found on GitHub. Falling back to compilation (this will take longer)..."
        USE_PRECOMPILED=false
        # Download and extract the entire repository tarball directly for compilation
        curl -fsSL "https://github.com/Azhar457/aegis-waf/archive/refs/heads/main.tar.gz" | tar -xz --strip-components=1
    fi

    # ── Generate Dockerfile ──────────────────────────────────────
    log_step "4" "Generating Dockerfile..."

    if [ "$USE_PRECOMPILED" = true ]; then
        local EBPF_COPY=""
        if [ -f "aegis-ebpf" ]; then
            EBPF_COPY="COPY aegis-ebpf /app/aegis-ebpf"
        fi

        cat > Dockerfile << DOCKERFILE_EOF
# ================================================================
# Aegis WAF — Precompiled Agent-Only Dockerfile
# ================================================================
FROM ubuntu:24.04
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/log/aegis-waf /app/certs

COPY aegis-waf /app/aegis-waf
RUN chmod +x /app/aegis-waf
${EBPF_COPY}
COPY config.toml /app/config.toml

EXPOSE 80 443

ENV RUST_LOG=info

CMD ["/app/aegis-waf", "--config", "/app/config.toml", "agent"]
DOCKERFILE_EOF
    else
        cat > Dockerfile << 'DOCKERFILE_EOF'
# ================================================================
# Aegis WAF — Lightweight Agent-Only Dockerfile (Compiler Fallback)
# ================================================================
FROM rust:slim-bookworm AS builder
WORKDIR /app

ENV CARGO_INCREMENTAL=0
ENV CARGO_BUILD_JOBS=2
ENV RUSTFLAGS="-C strip=symbols"

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY xtask/ ./xtask/

# Cache dependencies by building a dummy project first
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy real source code
COPY src/ ./src/

# Touch main.rs to force recompilation of our app, then build
RUN touch src/main.rs && \
    cargo build --release && \
    cp target/release/aegis-waf /app/aegis-waf-bin && \
    rm -rf target /usr/local/cargo/registry /usr/local/cargo/git

FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 curl && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/log/aegis-waf /app/certs

COPY --from=builder /app/aegis-waf-bin /app/aegis-waf
COPY config.toml /app/config.toml

EXPOSE 80 443

ENV RUST_LOG=info

CMD ["/app/aegis-waf", "--config", "/app/config.toml", "agent"]
DOCKERFILE_EOF
    fi

    log_success "Dockerfile generated."

    # ── Generate config.toml ─────────────────────────────────────
    log_step "5" "Generating config.toml..."

    local HOSTS_TOML=$(format_domains_toml)

    cat > config.toml << TOML_EOF
# ============================================================
# Aegis WAF — Agent Configuration (Auto-generated)
# ============================================================
# Generated by install.sh on $(date -u '+%Y-%m-%d %H:%M:%S UTC')
# ============================================================

certificates = []

[global]
port_http = ${HTTP_PORT}
port_https = ${HTTPS_PORT}
max_body_size = 10485760
default_rate_limit = ${RATE_LIMIT}
log_dir = "/var/log/aegis-waf"
log_level = "security"
waf_enabled = true

[logging]
mode = "${LOG_MODE}"
log_path = "/var/log/aegis-waf/aegis.log"
max_log_size_mb = 50
max_log_files = 5
blocklist_path = "/var/log/aegis-waf/blocklist.json"
TOML_EOF

    # Add remote URL if controller specified
    if [ -n "$CONTROLLER_URL" ]; then
        cat >> config.toml << TOML_REMOTE_EOF
remote_url = "${CONTROLLER_URL}"
push_interval_secs = 300
push_batch_size = 100
TOML_REMOTE_EOF
    fi

    cat >> config.toml << TOML_COMPONENTS_EOF

[components]
dashboard = false
clickhouse = false
service_discovery = false
geoip = true

[tls]
mode = "local_ca"
cert_dir = "./certs"

[[vhosts]]
name = "protected-app"
hosts = ${HOSTS_TOML}
backend = "${BACKEND_ADDR}"
rules = ["SQLI-*", "XSS-*", "LFI-*", "RFI-*", "SSRF-*", "CMDI-*", "BOT-*"]
blocked_countries = []
geoblock_type = "Blocklist"
ssl = "Auto (Local CA)"
max_body = "10MB"
rate_limit = "${RATE_LIMIT} req/min"
custom_rules = []

[vhosts.logging]
enabled = true
db_path = "/var/log/aegis-waf/aegis-waf.db"
TOML_COMPONENTS_EOF

    log_success "config.toml generated."

    # ── Generate docker-compose.yml ──────────────────────────────
    log_step "6" "Generating docker-compose.yml..."

    cat > docker-compose.yml << COMPOSE_EOF
services:
  aegis-agent:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: aegis_agent
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config.toml:/app/config.toml
      - ./certs:/app/certs
      - ./logs:/var/log/aegis-waf
    environment:
      - RUST_LOG=info
COMPOSE_EOF

    log_success "docker-compose.yml generated."
}

# ── Build and Start ──────────────────────────────────────────────
build_and_start() {
    cd "${INSTALL_DIR}"

    log_step "7" "Building Aegis WAF Docker image (this may take 3-5 minutes)..."
    echo ""
    docker compose build

    echo ""
    log_step "8" "Starting Aegis WAF Agent..."
    docker compose up -d

    echo ""
}

# ── Create management script ────────────────────────────────────
create_management_script() {
    cat > "${INSTALL_DIR}/aegis" << 'MGMT_EOF'
#!/bin/bash
# Aegis WAF Agent — Quick Management Commands
INSTALL_DIR="/opt/aegis-waf"
cd "$INSTALL_DIR"

case "${1:-help}" in
    start)
        docker compose up -d
        echo "Aegis WAF Agent started."
        ;;
    stop)
        docker compose down
        echo "Aegis WAF Agent stopped."
        ;;
    restart)
        docker compose restart
        echo "Aegis WAF Agent restarted."
        ;;
    status)
        docker compose ps
        echo ""
        echo "--- RAM Usage ---"
        docker stats aegis_agent --no-stream 2>/dev/null || echo "Container not running."
        ;;
    logs)
        docker compose logs -f --tail=100
        ;;
    waf-logs)
        tail -f "${INSTALL_DIR}/logs/aegis.log"
        ;;
    config)
        ${EDITOR:-nano} "${INSTALL_DIR}/config.toml"
        echo "Config updated. Run: aegis restart"
        ;;
    rebuild)
        docker compose down
        docker compose build
        docker compose up -d
        echo "Aegis WAF Agent rebuilt and started."
        ;;
    update)
        echo "Pulling latest source from GitHub..."
        mkdir -p /tmp/aegis-update
        curl -fsSL "https://github.com/Azhar457/aegis-waf/archive/refs/heads/main.tar.gz" | tar -xz -C /tmp/aegis-update --strip-components=1
        cp -r /tmp/aegis-update/src /tmp/aegis-update/Cargo.toml /tmp/aegis-update/Cargo.lock ./ 2>/dev/null || true
        rm -rf /tmp/aegis-update
        echo "Source updated. Run: aegis rebuild"
        ;;
    uninstall)
        read -p "Remove Aegis WAF completely? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            docker compose down --rmi all --volumes 2>/dev/null
            rm -f /usr/local/bin/aegis
            rm -rf /opt/aegis-waf
            echo "Aegis WAF has been uninstalled."
        fi
        ;;
    *)
        echo "Aegis WAF Agent — Management Commands"
        echo ""
        echo "Usage: aegis <command>"
        echo ""
        echo "  start       Start the WAF agent"
        echo "  stop        Stop the WAF agent"
        echo "  restart     Restart the WAF agent"
        echo "  status      Show container status and RAM usage"
        echo "  logs        Stream container logs"
        echo "  waf-logs    Stream WAF security logs (aegis.log)"
        echo "  config      Edit config.toml"
        echo "  rebuild     Rebuild and restart (after config/code changes)"
        echo "  update      Pull latest WAF rules from GitHub"
        echo "  uninstall   Remove Aegis WAF completely"
        ;;
esac
MGMT_EOF

    chmod +x "${INSTALL_DIR}/aegis"

    # Symlink to /usr/local/bin for global access
    ln -sf "${INSTALL_DIR}/aegis" /usr/local/bin/aegis

    log_success "Management script installed: ${BOLD}aegis${NC} command available globally."
}

# ── Print Success ────────────────────────────────────────────────
print_success() {
    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║                                                                  ║${NC}"
    echo -e "${GREEN}${BOLD}║   ✅  Aegis WAF Agent installed and running!                     ║${NC}"
    echo -e "${GREEN}${BOLD}║                                                                  ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Installation directory:${NC}  ${INSTALL_DIR}"
    echo -e "  ${BOLD}Config file:${NC}            ${INSTALL_DIR}/config.toml"
    echo -e "  ${BOLD}WAF security logs:${NC}      ${INSTALL_DIR}/logs/aegis.log"
    echo -e "  ${BOLD}TLS certificates:${NC}       ${INSTALL_DIR}/certs/"
    echo ""
    echo -e "  ${CYAN}${BOLD}── Quick Commands ──${NC}"
    echo -e "  ${BOLD}aegis status${NC}      Check container status and RAM usage"
    echo -e "  ${BOLD}aegis logs${NC}        Stream container logs"
    echo -e "  ${BOLD}aegis waf-logs${NC}    Stream WAF security logs"
    echo -e "  ${BOLD}aegis config${NC}      Edit configuration"
    echo -e "  ${BOLD}aegis restart${NC}     Restart after config changes"
    echo -e "  ${BOLD}aegis update${NC}      Pull latest WAF rules from GitHub"
    echo -e "  ${BOLD}aegis uninstall${NC}   Remove Aegis WAF"
    echo ""
    echo -e "  ${YELLOW}${BOLD}── Test WAF ──${NC}"
    echo -e "  ${DIM}# Normal request (should pass through to your app):${NC}"
    echo -e "  curl http://localhost:${HTTP_PORT}/"
    echo ""
    echo -e "  ${DIM}# SQL injection test (should return 403 Forbidden):${NC}"
    echo -e "  curl \"http://localhost:${HTTP_PORT}/?id=1' OR 1=1--\""
    echo ""
    echo -e "  ${DIM}# XSS test (should return 403 Forbidden):${NC}"
    echo -e "  curl \"http://localhost:${HTTP_PORT}/?q=<script>alert(1)</script>\""
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────
main() {
    print_banner
    preflight
    ensure_docker
    configure_interactively
    generate_files
    build_and_start
    create_management_script
    print_success
}

main "$@"
