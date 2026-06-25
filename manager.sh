#!/bin/bash

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/aegis-waf"
COMPOSE_CMD=""

# Print banner
print_banner() {
    clear
    echo -e "${BLUE}${BOLD}========================================================================${NC}"
    echo -e "${CYAN}${BOLD}                    🛡️  AEGIS WAF - SYSTEM MANAGER  🛡️                   ${NC}"
    echo -e "${BLUE}${BOLD}========================================================================${NC}"
}

# Check dependencies
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${YELLOW}Warning: docker could not be found.${NC}"
        return 1
    fi
    return 0
}

check_compose() {
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    elif command -v podman-compose &> /dev/null; then
        COMPOSE_CMD="podman-compose"
    else
        echo -e "${YELLOW}Warning: docker compose / podman-compose could not be found.${NC}"
        return 1
    fi
    return 0
}

# Install Aegis WAF
install_aegis() {
    print_banner
    echo -e "${BLUE}[*] Starting Aegis WAF installation...${NC}"
    
    # 1. Check docker
    if ! check_docker; then
        echo -e "${RED}[-] Error: Docker is required. Please install Docker first.${NC}"
        read -n 1 -s -r -p "Press any key to return to menu..."
        return
    fi
    
    # 2. Check compose
    if ! check_compose; then
        echo -e "${RED}[-] Error: Docker Compose / Podman Compose is required.${NC}"
        read -n 1 -s -r -p "Press any key to return to menu..."
        return
    fi
    
    # 3. Create install dir
    echo -e "${BLUE}[*] Creating installation directory at ${INSTALL_DIR}...${NC}"
    sudo mkdir -p "${INSTALL_DIR}"
    
    # 4. Copy docker-compose.yml and default config.toml
    echo -e "${BLUE}[*] Copying deployment files...${NC}"
    if [ -f "./docker-compose.yml" ]; then
        sudo cp ./docker-compose.yml "${INSTALL_DIR}/docker-compose.yml"
    else
        # Write docker-compose.yml content directly if run outside repo context
        cat << 'EOF' | sudo tee "${INSTALL_DIR}/docker-compose.yml" > /dev/null
services:
  aegis-controller:
    build: 
      context: .
      dockerfile: Dockerfile
    container_name: aegis_controller
    command: ["/app/aegis-waf", "controller"]
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - RUST_LOG=info
      - CLICKHOUSE_URL=http://clickhouse:8123
      - CLICKHOUSE_USER=default
      - CLICKHOUSE_PASSWORD=aegis
    volumes:
      - ./config.toml:/app/config.toml
    depends_on:
      clickhouse:
        condition: service_healthy

  clickhouse:
    image: clickhouse/clickhouse-server:latest
    container_name: aegis_clickhouse
    restart: unless-stopped
    environment:
      - CLICKHOUSE_USER=default
      - CLICKHOUSE_PASSWORD=aegis
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
name = "aegis-demo"
hosts = ["*.aegiswaf.demo"]
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
db_path = "logs/aegis-waf.db"
EOF
        fi
    fi

    # 5. Start containers
    echo -e "${BLUE}[*] Starting Aegis WAF Docker containers...${NC}"
    cd "${INSTALL_DIR}"
    sudo ${COMPOSE_CMD} up -d --build
    
    echo -e "${GREEN}[+] Aegis WAF started successfully!${NC}"
    echo -e "${YELLOW}Waiting for security initialisation...${NC}"
    sleep 3
    
    # Try to extract the generated admin token from config.toml
    if [ -f "${INSTALL_DIR}/config.toml" ]; then
        TOKEN=$(grep -oP 'admin_token = "\K[^"]+' "${INSTALL_DIR}/config.toml" || true)
        if [ -n "$TOKEN" ]; then
            echo -e "${GREEN}========================================================================${NC}"
            echo -e "${GREEN}  ADMINISTRATION TOKEN: ${YELLOW}${TOKEN}${NC}"
            echo -e "${GREEN}  Please save this token. You will need it to login to the dashboard.${NC}"
            echo -e "${GREEN}========================================================================${NC}"
        fi
    fi
    
    echo -e "${CYAN}Dashboard is available at: ${BOLD}http://localhost:8080${NC}"
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# Uninstall Aegis WAF
uninstall_aegis() {
    print_banner
    echo -e "${RED}${BOLD}[!] WARNING: This will completely remove Aegis WAF and ClickHouse databases!${NC}"
    read -p "Are you sure you want to proceed? (y/N) " confirm
    if [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]]; then
        if check_compose; then
            echo -e "${BLUE}[*] Stopping and removing containers...${NC}"
            if [ -d "${INSTALL_DIR}" ]; then
                cd "${INSTALL_DIR}"
                sudo ${COMPOSE_CMD} down -v
            fi
        fi
        echo -e "${BLUE}[*] Cleaning up installation directory...${NC}"
        sudo rm -rf "${INSTALL_DIR}"
        echo -e "${GREEN}[+] Aegis WAF uninstalled successfully.${NC}"
    else
        echo -e "${BLUE}[*] Uninstall cancelled.${NC}"
    fi
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# Upgrade Aegis WAF
upgrade_aegis() {
    print_banner
    echo -e "${BLUE}[*] Upgrading Aegis WAF...${NC}"
    if [ -d "${INSTALL_DIR}" ]; then
        cd "${INSTALL_DIR}"
        check_compose
        echo -e "${BLUE}[*] Pulling latest containers and rebuilding...${NC}"
        sudo ${COMPOSE_CMD} pull
        sudo ${COMPOSE_CMD} up -d --build
        echo -e "${GREEN}[+] Upgrade completed successfully.${NC}"
    else
        echo -e "${RED}[-] Error: Aegis WAF installation not found at ${INSTALL_DIR}.${NC}"
    fi
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# Show Status
show_status() {
    print_banner
    echo -e "${BLUE}[*] System Status:${NC}"
    if [ -d "${INSTALL_DIR}" ]; then
        cd "${INSTALL_DIR}"
        check_compose
        sudo ${COMPOSE_CMD} ps
        echo ""
        sudo ${COMPOSE_CMD} top
    else
        echo -e "${RED}[-] Error: Aegis WAF is not installed.${NC}"
    fi
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# Show Logs
show_logs() {
    print_banner
    echo -e "${BLUE}[*] Streaming logs (Press Ctrl+C to stop)...${NC}"
    if [ -d "${INSTALL_DIR}" ]; then
        cd "${INSTALL_DIR}"
        check_compose
        sudo ${COMPOSE_CMD} logs -f --tail 100
    else
        echo -e "${RED}[-] Error: Aegis WAF is not installed.${NC}"
        read -n 1 -s -r -p "Press any key to return to menu..."
    fi
}

# Run Formatters (Rust fmt & Prettier format)
run_formatters() {
    print_banner
    echo -e "${BLUE}[*] Running Rust Formatter (cargo fmt)...${NC}"
    if command -v cargo &> /dev/null; then
        cargo fmt
        echo -e "${GREEN}[+] Rust code formatted successfully.${NC}"
    else
        echo -e "${YELLOW}[!] Warning: cargo not found, skipping Rust formatting.${NC}"
    fi

    echo -e "${BLUE}[*] Running Frontend Formatter (npm run format)...${NC}"
    if [ -d "./dashboard" ]; then
        cd dashboard
        if command -v npm &> /dev/null; then
            npm run format
            echo -e "${GREEN}[+] Frontend code formatted successfully.${NC}"
        else
            echo -e "${YELLOW}[!] Warning: npm not found, skipping frontend formatting.${NC}"
        fi
        cd ..
    else
        echo -e "${YELLOW}[!] Warning: dashboard directory not found, skipping frontend formatting.${NC}"
    fi
    read -n 1 -s -r -p "Press any key to return to menu..."
}

# Parse command line arguments (Non-interactive mode)
if [ "$1" != "" ]; then
    case $1 in
        --install|install)
            install_aegis
            exit 0
            ;;
        --uninstall|uninstall)
            uninstall_aegis
            exit 0
            ;;
        --upgrade|upgrade)
            upgrade_aegis
            exit 0
            ;;
        --status|status)
            show_status
            exit 0
            ;;
        --logs|logs)
            show_logs
            exit 0
            ;;
        --format|format)
            run_formatters
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [install|uninstall|upgrade|status|logs|format]"
            exit 1
            ;;
    esac
fi

# Main Loop (Interactive mode)
while true; do
    print_banner
    echo -e "  1) ${GREEN}Install / Start Aegis WAF${NC}"
    echo -e "  2) ${RED}Uninstall Aegis WAF${NC}"
    echo -e "  3) ${BLUE}Upgrade Aegis WAF${NC}"
    echo -e "  4) ${CYAN}Show Service Status${NC}"
    echo -e "  5) ${YELLOW}View Real-time Logs${NC}"
    echo -e "  6) ${CYAN}Run Linters & Formatters (Rust & Svelte)${NC}"
    echo -e "  7) Exit"
    echo ""
    read -p "Select an option [1-7]: " opt
    case $opt in
        1) install_aegis ;;
        2) uninstall_aegis ;;
        3) upgrade_aegis ;;
        4) show_status ;;
        5) show_logs ;;
        6) run_formatters ;;
        7) exit 0 ;;
        *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
    esac
done
