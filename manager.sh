#!/bin/bash

# ================================================================
#  🛡️  jarsWAF - SYSTEM MANAGER
#  All-in-one installer, builder, and deployment tool
#  Supports: Ubuntu/Debian, RHEL/CentOS/Fedora, macOS
# ================================================================

set -e

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# --- Constants ---
INSTALL_DIR="/opt/jarswaf"
COMPOSE_CMD=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQUIRED_RUST_VERSION="1.75.0"
REQUIRED_NODE_VERSION="20"

# ================================================================
#  UTILITY FUNCTIONS
# ================================================================

print_banner() {
    clear
    echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}${BOLD}║${NC}${CYAN}${BOLD}           🛡️  jarsWAF — SYSTEM MANAGER v2.0  🛡️              ${NC}${BLUE}${BOLD}║${NC}"
    echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[  OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[FAIL]${NC} $1"; }
log_step()    { echo -e "\n${MAGENTA}${BOLD}━━━ Step $1: $2 ━━━${NC}"; }

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$PRETTY_NAME"
    elif [ "$(uname)" = "Darwin" ]; then
        OS_ID="macos"
        OS_NAME="macOS $(sw_vers -productVersion)"
    else
        OS_ID="unknown"
        OS_NAME="Unknown OS"
    fi
    log_info "Detected OS: ${BOLD}${OS_NAME}${NC}"
}

detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MGR="apt"
        PKG_INSTALL="sudo apt-get install -y"
        PKG_UPDATE="sudo apt-get update -y"
    elif command -v dnf &> /dev/null; then
        PKG_MGR="dnf"
        PKG_INSTALL="sudo dnf install -y"
        PKG_UPDATE="sudo dnf check-update || true"
    elif command -v yum &> /dev/null; then
        PKG_MGR="yum"
        PKG_INSTALL="sudo yum install -y"
        PKG_UPDATE="sudo yum check-update || true"
    elif command -v brew &> /dev/null; then
        PKG_MGR="brew"
        PKG_INSTALL="brew install"
        PKG_UPDATE="brew update"
    elif command -v pacman &> /dev/null; then
        PKG_MGR="pacman"
        PKG_INSTALL="sudo pacman -S --noconfirm"
        PKG_UPDATE="sudo pacman -Sy"
    else
        PKG_MGR="unknown"
        log_error "No supported package manager found!"
        return 1
    fi
    log_info "Package manager: ${BOLD}${PKG_MGR}${NC}"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_warn "Docker not found."
        return 1
    fi
    log_success "Docker found: $(docker --version)"
    return 0
}

check_compose() {
    if docker compose version &> /dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    elif command -v podman-compose &> /dev/null; then
        COMPOSE_CMD="podman-compose"
    else
        log_warn "Docker Compose / Podman Compose not found."
        return 1
    fi
    log_success "Compose found: ${COMPOSE_CMD}"
    return 0
}

check_rust() {
    if ! command -v rustc &> /dev/null; then
        log_warn "Rust toolchain not found."
        return 1
    fi
    local ver
    ver=$(rustc --version | grep -oP '\d+\.\d+\.\d+')
    log_success "Rust found: rustc ${ver}"
    return 0
}

check_node() {
    if ! command -v node &> /dev/null; then
        log_warn "Node.js not found."
        return 1
    fi
    local ver
    ver=$(node --version)
    log_success "Node.js found: ${ver}"
    return 0
}

check_cargo() {
    if ! command -v cargo &> /dev/null; then
        log_warn "Cargo not found."
        return 1
    fi
    log_success "Cargo found: $(cargo --version)"
    return 0
}

# ================================================================
#  DEPENDENCY INSTALLATION
# ================================================================

install_system_deps() {
    log_step "1" "Installing system build dependencies"

    case "$PKG_MGR" in
        apt)
            $PKG_UPDATE
            $PKG_INSTALL build-essential pkg-config libssl-dev curl wget git ca-certificates gnupg lsb-release
            ;;
        dnf|yum)
            $PKG_UPDATE
            $PKG_INSTALL gcc gcc-c++ make pkgconfig openssl-devel curl wget git ca-certificates
            ;;
        brew)
            $PKG_INSTALL openssl pkg-config curl git
            ;;
        pacman)
            $PKG_UPDATE
            $PKG_INSTALL base-devel openssl pkg-config curl wget git
            ;;
        *)
            log_error "Cannot install system deps for package manager: ${PKG_MGR}"
            return 1
            ;;
    esac
    log_success "System build dependencies installed."
}

install_rust() {
    log_step "2" "Installing Rust toolchain"

    if check_rust; then
        log_info "Rust is already installed. Skipping."
        return 0
    fi

    log_info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

    # Source cargo env for current session
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi

    if check_rust; then
        log_success "Rust installed successfully."
    else
        log_error "Rust installation failed. Please install manually: https://rustup.rs"
        return 1
    fi
}

install_node() {
    log_step "3" "Installing Node.js v${REQUIRED_NODE_VERSION}"

    if check_node; then
        local major
        major=$(node --version | grep -oP '(?<=v)\d+')
        if [ "$major" -ge "$REQUIRED_NODE_VERSION" ]; then
            log_info "Node.js v${major} meets requirement (>= v${REQUIRED_NODE_VERSION}). Skipping."
            return 0
        fi
        log_warn "Node.js v${major} is below required v${REQUIRED_NODE_VERSION}. Upgrading..."
    fi

    case "$PKG_MGR" in
        apt)
            log_info "Installing Node.js via NodeSource..."
            # Add NodeSource repository
            if [ ! -f /etc/apt/sources.list.d/nodesource.list ]; then
                curl -fsSL https://deb.nodesource.com/setup_${REQUIRED_NODE_VERSION}.x | sudo -E bash -
            fi
            $PKG_INSTALL nodejs
            ;;
        dnf|yum)
            curl -fsSL https://rpm.nodesource.com/setup_${REQUIRED_NODE_VERSION}.x | sudo bash -
            $PKG_INSTALL nodejs
            ;;
        brew)
            brew install node@${REQUIRED_NODE_VERSION}
            ;;
        pacman)
            $PKG_INSTALL nodejs npm
            ;;
        *)
            log_error "Cannot install Node.js for package manager: ${PKG_MGR}"
            return 1
            ;;
    esac

    if check_node; then
        log_success "Node.js installed successfully."
    else
        log_error "Node.js installation failed."
        return 1
    fi
}

install_docker() {
    log_step "4" "Installing Docker Engine"

    if check_docker; then
        log_info "Docker is already installed. Skipping."
        return 0
    fi

    case "$OS_ID" in
        ubuntu|debian)
            log_info "Installing Docker via official script..."
            curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
            sudo sh /tmp/get-docker.sh
            rm -f /tmp/get-docker.sh

            # Add current user to docker group
            sudo usermod -aG docker "$USER"
            log_warn "You may need to logout and login again for Docker group to take effect."
            ;;
        centos|rhel|fedora|rocky|almalinux)
            curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
            sudo sh /tmp/get-docker.sh
            rm -f /tmp/get-docker.sh
            sudo usermod -aG docker "$USER"
            ;;
        macos)
            log_warn "Please install Docker Desktop from: https://docker.com/products/docker-desktop"
            log_warn "Then re-run this script."
            return 1
            ;;
        *)
            log_error "Automatic Docker installation not supported for ${OS_ID}."
            log_info "Please install Docker manually: https://docs.docker.com/engine/install/"
            return 1
            ;;
    esac

    # Enable and start Docker service
    if command -v systemctl &> /dev/null; then
        sudo systemctl enable docker
        sudo systemctl start docker
    fi

    if check_docker; then
        log_success "Docker installed and running."
    else
        log_error "Docker installation failed."
        return 1
    fi
}

# ================================================================
#  FULL DEPENDENCY SETUP (Zero-to-Ready)
# ================================================================

setup_all_dependencies() {
    print_banner
    echo -e "${CYAN}${BOLD}  This will install ALL required dependencies from scratch.${NC}"
    echo -e "${CYAN}  Target: Ubuntu/Debian Minimal Server (also supports RHEL, macOS)${NC}"
    echo ""
    echo -e "  The following will be installed if missing:"
    echo -e "    ${GREEN}✓${NC} System build tools (gcc, pkg-config, libssl-dev, git, curl)"
    echo -e "    ${GREEN}✓${NC} Rust toolchain (via rustup)"
    echo -e "    ${GREEN}✓${NC} Node.js v${REQUIRED_NODE_VERSION} (via NodeSource)"
    echo -e "    ${GREEN}✓${NC} Docker Engine + Docker Compose"
    echo ""
    read -p "Proceed with installation? (Y/n) " confirm
    if [[ "$confirm" == [nN] ]]; then
        log_info "Installation cancelled."
        read -n 1 -s -r -p "Press any key to return to menu..."
        return
    fi

    detect_os
    detect_package_manager

    install_system_deps
    install_rust
    install_node
    install_docker

    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║  ✅  ALL DEPENDENCIES INSTALLED SUCCESSFULLY!                   ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Summary:"
    check_rust    || true
    check_node    || true
    check_docker  || true
    check_compose || true
    echo ""
    log_warn "If Docker was just installed, please ${BOLD}logout and login${NC} to apply group changes."
    log_info "Next: run ${BOLD}./manager.sh build${NC} to compile from source, or ${BOLD}./manager.sh install${NC} for Docker deployment."
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# ================================================================
#  BUILD FROM SOURCE
# ================================================================

build_from_source() {
    print_banner
    echo -e "${CYAN}${BOLD}  Building jarsWAF from source...${NC}"
    echo ""

    cd "$SCRIPT_DIR"

    # Source cargo env if available
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi

    # 1. Check Rust
    log_step "1" "Verifying Rust toolchain"
    if ! check_rust || ! check_cargo; then
        log_error "Rust toolchain not found. Run: ${BOLD}./manager.sh deps${NC}"
        read -n 1 -s -r -p "Press any key to return to menu..."
        return 1
    fi

    # 2. Check Node.js
    log_step "2" "Verifying Node.js"
    if ! check_node; then
        log_error "Node.js not found. Run: ${BOLD}./manager.sh deps${NC}"
        read -n 1 -s -r -p "Press any key to return to menu..."
        return 1
    fi

    # 3. Install dashboard dependencies
    log_step "3" "Installing dashboard npm dependencies"
    if [ -d "./dashboard" ]; then
        cd dashboard
        npm install
        log_success "Dashboard dependencies installed."
        cd "$SCRIPT_DIR"
    else
        log_error "Dashboard directory not found!"
        return 1
    fi

    # 4. Build dashboard
    log_step "4" "Building dashboard (Svelte/Vite)"
    cd dashboard
    npm run build
    log_success "Dashboard built to dashboard/dist/"
    cd "$SCRIPT_DIR"

    # 5. Build Rust backend
    log_step "5" "Building Rust backend (release mode)"
    cargo build --release --workspace
    log_success "Backend built to target/release/"

    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║  ✅  BUILD COMPLETED SUCCESSFULLY!                              ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Unified Binary: ${BOLD}${SCRIPT_DIR}/target/release/jarswaf${NC}"
    echo -e "  Agent Binary:   ${BOLD}${SCRIPT_DIR}/target/release/agent${NC}"
    echo -e "  Controller:     ${BOLD}${SCRIPT_DIR}/target/release/controller${NC}"
    echo -e "  Dashboard:      ${BOLD}${SCRIPT_DIR}/dashboard/dist/${NC}"
    echo ""
    echo -e "  Run in dev mode:  ${BOLD}./manager.sh dev${NC}"
    echo -e "  Deploy via Docker: ${BOLD}./manager.sh install${NC}"
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# ================================================================
#  DEVELOPMENT MODE
# ================================================================

run_dev_mode() {
    print_banner
    echo -e "${CYAN}${BOLD}  Starting jarsWAF in Development Mode...${NC}"
    echo ""

    cd "$SCRIPT_DIR"

    # Source cargo env
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi

    # 1. Start ClickHouse
    log_step "1" "Starting ClickHouse via Docker"
    if ! check_docker; then
        log_error "Docker is required for ClickHouse. Run: ${BOLD}./manager.sh deps${NC}"
        read -n 1 -s -r -p "Press any key to return to menu..."
        return 1
    fi
    check_compose
    ${COMPOSE_CMD} up -d clickhouse
    log_success "ClickHouse started."

    log_step "2" "Waiting for ClickHouse to be healthy..."
    sleep 5

    # Export ClickHouse credentials
    export CLICKHOUSE_USER=default
    export CLICKHOUSE_PASSWORD=jarswaf

    # Trap to cleanup child processes
    cleanup() {
        echo ""
        log_info "Stopping all jarsWAF processes..."
        kill "$PID_CONTROLLER" "$PID_AGENT" "$PID_VITE" 2>/dev/null || true
        exit
    }
    trap cleanup SIGINT SIGTERM

    log_step "3" "Starting WAF Controller"
    cargo run -- controller &
    PID_CONTROLLER=$!
    sleep 2

    log_step "4" "Starting WAF Agent"
    cargo run -- agent --controller http://localhost:8080 &
    PID_AGENT=$!

    log_step "5" "Starting Dashboard Dev Server (Vite)"
    cd dashboard && npm run dev &
    PID_VITE=$!
    cd "$SCRIPT_DIR"

    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║  ✅  ALL DEVELOPMENT SERVICES RUNNING!                          ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Dashboard UI:   ${BOLD}http://localhost:5173/${NC}"
    echo -e "  Controller API: ${BOLD}http://localhost:8080/${NC}"
    echo -e "  ClickHouse:     ${BOLD}http://localhost:8123/${NC}"
    echo ""
    echo -e "  Press ${BOLD}Ctrl+C${NC} to stop all processes."
    echo -e "${BLUE}${BOLD}══════════════════════════════════════════════════════════════════${NC}"

    wait
}

# ================================================================
#  DOCKER PRODUCTION DEPLOYMENT
# ================================================================

install_jarswaf() {
    print_banner
    echo -e "${CYAN}${BOLD}  Deploying jarsWAF via Docker (Production)...${NC}"
    echo ""

    # 1. Check Docker
    if ! check_docker; then
        log_error "Docker is required. Run: ${BOLD}./manager.sh deps${NC}"
        read -n 1 -s -r -p "Press any key to return to menu..."
        return
    fi

    # 2. Check Compose
    if ! check_compose; then
        log_error "Docker Compose is required. Run: ${BOLD}./manager.sh deps${NC}"
        read -n 1 -s -r -p "Press any key to return to menu..."
        return
    fi

    # 3. Create install dir
    log_step "1" "Creating installation directory"
    sudo mkdir -p "${INSTALL_DIR}"

    # 4. Copy deployment files
    log_step "2" "Copying deployment files"
    cd "$SCRIPT_DIR"
    if [ -f "./docker-compose.yml" ]; then
        sudo cp ./docker-compose.yml "${INSTALL_DIR}/docker-compose.yml"
        log_success "docker-compose.yml copied."
    else
        log_info "Generating docker-compose.yml..."
        cat << 'EOF' | sudo tee "${INSTALL_DIR}/docker-compose.yml" > /dev/null
services:
  jarswaf-controller:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: jarswaf_controller
    command: ["/app/jarswaf", "controller"]
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - RUST_LOG=info
      - CLICKHOUSE_URL=http://clickhouse:8123
      - CLICKHOUSE_USER=default
      - CLICKHOUSE_PASSWORD=jarswaf
    volumes:
      - ./config.toml:/app/config.toml
    depends_on:
      clickhouse:
        condition: service_healthy

  clickhouse:
    image: clickhouse/clickhouse-server:latest
    container_name: jarswaf_clickhouse
    restart: unless-stopped
    environment:
      - CLICKHOUSE_USER=default
      - CLICKHOUSE_PASSWORD=jarswaf
      - CLICKHOUSE_DB=default
    ports:
      - "8123:8123"
      - "9000:9000"
    volumes:
      - clickhouse_data:/var/lib/clickhouse
    ulimits:
      nofile:
        soft: 262144
        hard: 262144
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8123/ping"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  clickhouse_data:
EOF
        log_success "docker-compose.yml generated."
    fi

    # Copy Dockerfile if in repo context
    if [ -f "./Dockerfile" ]; then
        sudo cp ./Dockerfile "${INSTALL_DIR}/Dockerfile"
        log_success "Dockerfile copied."
    fi

    # Copy source directories needed for Docker build
    if [ -d "./src" ]; then
        sudo cp -r ./src "${INSTALL_DIR}/src"
        sudo cp -r ./dashboard "${INSTALL_DIR}/dashboard"
        sudo cp -r ./xtask "${INSTALL_DIR}/xtask"
        sudo cp ./Cargo.toml ./Cargo.lock "${INSTALL_DIR}/"
        log_success "Source files copied for Docker build."
    fi

    # Create default config.toml if not exists
    if [ ! -f "${INSTALL_DIR}/config.toml" ]; then
        if [ -f "./config.toml" ]; then
            sudo cp ./config.toml "${INSTALL_DIR}/config.toml"
        else
            cat << 'EOF' | sudo tee "${INSTALL_DIR}/config.toml" > /dev/null
certificates = []

[global]
port_http = 80
port_https = 443
max_body_size = 10485760
default_rate_limit = 600
log_dir = "./logs"
log_level = "verbose"
waf_enabled = true

[tls]
mode = "local_ca"
cert_dir = "./certs"

[[vhosts]]
name = "jarswaf-demo"
hosts = ["*.jarswafwaf.demo"]
backend = "127.0.0.1:8080"
rules = ["SQLI-*", "XSS-*", "LFI-*", "RFI-*", "SSRF-*", "CMDI-*", "BOT-*"]
blocked_countries = []
geoblock_type = "Blocklist"
ssl = "Auto (Local CA)"
max_body = "10MB"
rate_limit = "600 req/min"
custom_rules = []

[vhosts.logging]
enabled = true
db_path = "logs/jarswaf.db"
EOF
        fi
        log_success "config.toml created."
    fi

    # 5. Build and start containers
    log_step "3" "Building and starting Docker containers"
    cd "${INSTALL_DIR}"
    sudo ${COMPOSE_CMD} up -d --build

    log_success "Docker containers started!"

    log_step "4" "Waiting for services to initialize..."
    sleep 5

    # Extract admin token
    if [ -f "${INSTALL_DIR}/config.toml" ]; then
        TOKEN=$(grep -oP 'admin_token = "\K[^"]+' "${INSTALL_DIR}/config.toml" 2>/dev/null || true)
        if [ -n "$TOKEN" ]; then
            echo ""
            echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}${BOLD}║  🔑 ADMIN TOKEN: ${YELLOW}${TOKEN}${GREEN}${BOLD}   ║${NC}"
            echo -e "${GREEN}${BOLD}║  Save this token! You need it to login to the dashboard.       ║${NC}"
            echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
        fi
    fi

    echo ""
    echo -e "${GREEN}${BOLD}  ✅  jarsWAF deployed successfully!${NC}"
    echo -e "  Dashboard: ${BOLD}http://localhost:8080${NC}"
    echo ""
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# ================================================================
#  UNINSTALL
# ================================================================

uninstall_jarswaf() {
    print_banner
    echo -e "${RED}${BOLD}  ⚠️  WARNING: This will PERMANENTLY remove jarsWAF!${NC}"
    echo -e "${RED}  This includes all containers, volumes, and configuration.${NC}"
    echo ""
    read -p "Are you sure? Type 'yes' to confirm: " confirm
    if [[ "$confirm" != "yes" ]]; then
        log_info "Uninstall cancelled."
        read -n 1 -s -r -p "Press any key to return to menu..."
        return
    fi

    if check_compose; then
        if [ -d "${INSTALL_DIR}" ]; then
            log_info "Stopping and removing containers..."
            cd "${INSTALL_DIR}"
            sudo ${COMPOSE_CMD} down -v
        fi
    fi

    log_info "Removing installation directory..."
    sudo rm -rf "${INSTALL_DIR}"
    log_success "jarsWAF uninstalled completely."
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# ================================================================
#  UPGRADE
# ================================================================

upgrade_jarswaf() {
    print_banner
    echo -e "${CYAN}${BOLD}  Upgrading jarsWAF...${NC}"
    echo ""

    if [ -d "${INSTALL_DIR}" ]; then
        cd "${INSTALL_DIR}"
        check_compose
        log_info "Pulling latest images and rebuilding..."
        sudo ${COMPOSE_CMD} pull
        sudo ${COMPOSE_CMD} up -d --build
        log_success "Upgrade completed!"
    else
        log_error "jarsWAF not found at ${INSTALL_DIR}. Run ${BOLD}./manager.sh install${NC} first."
    fi
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# ================================================================
#  STATUS & HEALTH CHECK
# ================================================================

show_status() {
    print_banner
    echo -e "${CYAN}${BOLD}  System Status & Health Check${NC}"
    echo ""

    # Check dependencies
    echo -e "${BLUE}${BOLD}── Dependencies ──${NC}"
    check_rust    || log_warn "Rust not installed"
    check_node    || log_warn "Node.js not installed"
    check_docker  || log_warn "Docker not installed"
    check_compose || log_warn "Docker Compose not installed"
    echo ""

    # Docker services
    if check_docker &> /dev/null && check_compose &> /dev/null; then
        echo -e "${BLUE}${BOLD}── Docker Services ──${NC}"
        if [ -d "${INSTALL_DIR}" ]; then
            cd "${INSTALL_DIR}"
            sudo ${COMPOSE_CMD} ps 2>/dev/null || true
        elif [ -f "${SCRIPT_DIR}/docker-compose.yml" ]; then
            cd "$SCRIPT_DIR"
            ${COMPOSE_CMD} ps 2>/dev/null || true
        else
            log_info "No deployment found."
        fi
        echo ""

        # Health check endpoints
        echo -e "${BLUE}${BOLD}── Endpoint Health ──${NC}"
        if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 2>/dev/null | grep -qP '(200|301|302)'; then
            log_success "Controller API (http://localhost:8080) — ${GREEN}REACHABLE${NC}"
        else
            log_warn "Controller API (http://localhost:8080) — ${RED}UNREACHABLE${NC}"
        fi

        if curl -s -o /dev/null -w "%{http_code}" http://localhost:8123/ping 2>/dev/null | grep -q '200'; then
            log_success "ClickHouse    (http://localhost:8123) — ${GREEN}HEALTHY${NC}"
        else
            log_warn "ClickHouse    (http://localhost:8123) — ${RED}UNREACHABLE${NC}"
        fi
    fi

    echo ""
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# ================================================================
#  LOGS
# ================================================================

show_logs() {
    print_banner
    echo -e "${CYAN}${BOLD}  Streaming logs (Ctrl+C to stop)...${NC}"
    echo ""

    if [ -d "${INSTALL_DIR}" ]; then
        cd "${INSTALL_DIR}"
        check_compose
        sudo ${COMPOSE_CMD} logs -f --tail 100
    elif [ -f "${SCRIPT_DIR}/docker-compose.yml" ]; then
        cd "$SCRIPT_DIR"
        check_compose
        ${COMPOSE_CMD} logs -f --tail 100
    else
        log_error "No deployment found."
        read -n 1 -s -r -p "Press any key to return to menu..."
    fi
}

# ================================================================
#  FORMATTERS & LINTERS
# ================================================================

run_formatters() {
    print_banner
    echo -e "${CYAN}${BOLD}  Running Linters & Formatters${NC}"
    echo ""

    cd "$SCRIPT_DIR"

    # Source cargo env
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi

    # Rust
    echo -e "${BLUE}${BOLD}── Rust ──${NC}"
    if command -v cargo &> /dev/null; then
        log_info "Running cargo fmt..."
        cargo fmt -- --check && log_success "Rust formatting OK" || log_warn "Rust formatting issues found. Run: cargo fmt"

        log_info "Running cargo clippy..."
        cargo clippy -- -D warnings 2>&1 && log_success "Clippy: no warnings" || log_warn "Clippy found issues"

        log_info "Running cargo test..."
        cargo test 2>&1 && log_success "All tests passed" || log_warn "Some tests failed"
    else
        log_warn "Cargo not found, skipping Rust checks."
    fi

    echo ""

    # Frontend
    echo -e "${BLUE}${BOLD}── Frontend (Svelte/TypeScript) ──${NC}"
    if [ -d "./dashboard" ]; then
        cd dashboard
        if command -v npm &> /dev/null; then
            log_info "Running svelte-check..."
            npm run check 2>&1 && log_success "Svelte type-check OK" || log_warn "Type-check issues found"

            log_info "Running Prettier..."
            npx prettier --check . 2>&1 && log_success "Formatting OK" || log_warn "Formatting issues found. Run: npm run format"
        else
            log_warn "npm not found, skipping frontend checks."
        fi
        cd "$SCRIPT_DIR"
    else
        log_warn "Dashboard directory not found."
    fi

    echo ""
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# ================================================================
#  AGENT-ONLY DEPLOYMENT (Lightweight VPS)
# ================================================================

deploy_agent_only() {
    print_banner
    echo -e "${CYAN}${BOLD}  Deploying jarsWAF Agent Only (Lightweight Mode)${NC}"
    echo -e "${DIM}  No ClickHouse, No Dashboard — just the WAF proxy (~30MB RAM)${NC}"
    echo ""

    # Check Docker
    if ! check_docker; then
        log_error "Docker is required. Run: ${BOLD}./manager.sh deps${NC}"
        read -n 1 -s -r -p "Press any key to return to menu..."
        return
    fi

    if ! check_compose; then
        log_error "Docker Compose is required. Run: ${BOLD}./manager.sh deps${NC}"
        read -n 1 -s -r -p "Press any key to return to menu..."
        return
    fi

    cd "$SCRIPT_DIR"

    # Check for agent compose file
    if [ ! -f "docker-compose.agent.yml" ]; then
        log_error "docker-compose.agent.yml not found!"
        read -n 1 -s -r -p "Press any key to return to menu..."
        return
    fi

    # Check for standalone config
    if [ ! -f "config.standalone.toml" ]; then
        log_error "config.standalone.toml not found!"
          log_step "1" "Building Rust Agent binary (release mode)"
    cargo build --release --bin agent

    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║  ✅  AGENT BUILD COMPLETED!                                     ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Binary: ${BOLD}${SCRIPT_DIR}/target/release/agent${NC}"
    echo ""
    echo -e "  Run standalone:"
    echo -e "    ${BOLD}./target/release/agent --config config.standalone.toml${NC}"
    echo ""
    echo -e "  Run with remote controller:"
    echo -e "    ${BOLD}./target/release/agent --config config.standalone.toml --controller http://CENTRAL_IP:8080${NC}"
    read -n 1 -s -r -p "Press any key to return to menu..."�════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Config:     ${BOLD}config.standalone.toml${NC}"
    echo -e "  Logs:       ${BOLD}/var/log/jarswaf/jarswaf.log${NC} (inside container)"
    echo -e "  HTTP Proxy: ${BOLD}http://0.0.0.0:80${NC}"
    echo ""
    echo -e "  Edit ${BOLD}config.standalone.toml${NC} to configure your VHosts and backends."
    read -n 1 -s -r -p "Press any key to return to menu..."
}

build_agent_only() {
    print_banner
    echo -e "${CYAN}${BOLD}  Building jarsWAF Agent binary only (no dashboard)...${NC}"
    echo ""

    cd "$SCRIPT_DIR"

    # Source cargo env
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi

    if ! check_rust || ! check_cargo; then
        log_error "Rust toolchain not found. Run: ${BOLD}./manager.sh deps${NC}"
        read -n 1 -s -r -p "Press any key to return to menu..."
        return 1
    fi

    log_step "1" "Building Rust binary (release mode, no dashboard)"
    cargo build --release

    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║  ✅  AGENT BUILD COMPLETED!                                     ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Binary: ${BOLD}${SCRIPT_DIR}/target/release/jarswaf${NC}"
    echo ""
    echo -e "  Run standalone:"
    echo -e "    ${BOLD}./target/release/jarswaf agent --config config.standalone.toml${NC}"
    echo ""
    echo -e "  Run with remote controller:"
    echo -e "    ${BOLD}./target/release/jarswaf agent --config config.standalone.toml --controller http://CENTRAL_IP:8080${NC}"
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# ================================================================
#  CLI ARGUMENT PARSING (Non-interactive)
# ================================================================

if [ "$1" != "" ]; then
    case $1 in
        --deps|deps|setup)
            setup_all_dependencies
            exit 0
            ;;
        --build|build)
            build_from_source
            exit 0
            ;;
        --dev|dev)
            run_dev_mode
            exit 0
            ;;
        --install|install|deploy)
            install_jarswaf
            exit 0
            ;;
        --agent-deploy|agent-deploy)
            deploy_agent_only
            exit 0
            ;;
        --agent-build|agent-build)
            build_agent_only
            exit 0
            ;;
        --uninstall|uninstall|remove)
            uninstall_jarswaf
            exit 0
            ;;
        --upgrade|upgrade|update)
            upgrade_jarswaf
            exit 0
            ;;
        --status|status|health)
            show_status
            exit 0
            ;;
        --logs|logs)
            show_logs
            exit 0
            ;;
        --format|format|lint|check)
            run_formatters
            exit 0
            ;;
        --help|help|-h)
            echo "jarsWAF System Manager"
            echo ""
            echo "Usage: $0 [COMMAND]"
            echo ""
            echo "Full Stack Commands:"
            echo "  deps, setup       Install ALL system dependencies (Rust, Node.js, Docker)"
            echo "  build             Build full stack from source (Rust + Svelte)"
            echo "  dev               Start development mode (Controller + Agent + Vite)"
            echo "  install, deploy   Deploy full stack via Docker (production)"
            echo ""
            echo "Lightweight Agent Commands (for small VPS):"
            echo "  agent-deploy      Deploy Agent-only via Docker (no ClickHouse, no Dashboard)"
            echo "  agent-build       Build Agent binary only (no dashboard build)"
            echo ""
            echo "Management Commands:"
            echo "  uninstall         Remove jarsWAF completely"
            echo "  upgrade           Pull latest and rebuild containers"
            echo "  status, health    Show system status and health checks"
            echo "  logs              Stream Docker container logs"
            echo "  format, lint      Run linters and formatters (Rust + Svelte)"
            echo "  help              Show this help message"
            echo ""
            echo "Interactive mode: Run without arguments for menu-driven interface."
            exit 0
            ;;
        *)
            echo "Unknown command: $1"
            echo "Run '$0 help' for usage information."
            exit 1
            ;;
    esac
fi

# ================================================================
#  INTERACTIVE MENU
# ================================================================

while true; do
    print_banner
    echo -e "  ${GREEN}1)${NC}  📦 Install ALL Dependencies (Zero-to-Ready Setup)"
    echo -e "  ${GREEN}2)${NC}  🔨 Build from Source (Full Stack: Rust + Svelte)"
    echo -e "  ${GREEN}3)${NC}  🚀 Development Mode (Controller + Agent + Vite)"
    echo -e "  ${BLUE}4)${NC}  🐳 Deploy Full Stack via Docker (Production)"
    echo -e "  ${CYAN}5)${NC}  ⬆️  Upgrade Docker Deployment"
    echo -e ""
    echo -e "  ${YELLOW}${BOLD}── Lightweight VPS ──${NC}"
    echo -e "  ${YELLOW}6)${NC}  🪶 Deploy Agent Only (No ClickHouse, ~30MB RAM)"
    echo -e "  ${YELLOW}7)${NC}  🔧 Build Agent Binary Only"
    echo -e ""
    echo -e "  ${CYAN}${BOLD}── Management ──${NC}"
    echo -e "  ${RED}8)${NC}  🗑️  Uninstall jarsWAF"
    echo -e "  ${CYAN}9)${NC}  📊 System Status & Health Check"
    echo -e "  ${DIM}10)${NC} 📋 View Real-time Logs"
    echo -e "  ${MAGENTA}11)${NC} 🧹 Run Linters & Formatters"
    echo -e "  ${DIM}0)${NC}  Exit"
    echo ""
    read -p "  Select [0-11]: " opt
    case $opt in
        1) setup_all_dependencies ;;
        2) build_from_source ;;
        3) run_dev_mode ;;
        4) install_jarswaf ;;
        5) upgrade_jarswaf ;;
        6) deploy_agent_only ;;
        7) build_agent_only ;;
        8) uninstall_jarswaf ;;
        9) show_status ;;
        10) show_logs ;;
        11) run_formatters ;;
        0) echo -e "${CYAN}Goodbye! 🛡️${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
    esac
done

