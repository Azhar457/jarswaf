#!/bin/bash
set -uo pipefail

echo "================================================="
echo " 🛡️ jarsWAF Agent Installation (Linux / macOS)"
echo "================================================="

if [ -z "$CONTROLLER_IP" ]; then
  echo "Error: CONTROLLER_IP environment variable not set."
  echo "Usage: curl -fsSL https://<IP>:8080/install.sh | CONTROLLER_IP=<IP>:8080 bash"
  exit 1
fi

# Sanitize CONTROLLER_IP before it ever reaches a heredoc or command interpolation.
# Allow only host:port characters (digits, dots, dashes, colons, brackets for IPv6).
# `ponytail:` if a hostname (not IP) is ever supported here, validate it against a
# hostname regex; currently the controller advertises an IP literal.
if ! printf '%s' "$CONTROLLER_IP" | grep -Eq '^[0-9A-Za-z.:_-]+$'; then
  echo "Error: CONTROLLER_IP contains invalid characters."
  exit 1
fi

# Prefer HTTPS; fall back to HTTP only when the operator explicitly opts in via
# JARSWAF_CONTROLLER_SCHEME=http (e.g. lab/CTF where the controller has no TLS yet).
PROTO="${JARSWAF_CONTROLLER_SCHEME:-https}"
if [ "$PROTO" != "http" ] && [ "$PROTO" != "https" ]; then
  echo "Error: JARSWAF_CONTROLLER_SCHEME must be 'http' or 'https'."
  exit 1
fi

echo "[*] Connecting to jarsWAF Central Controller at: ${PROTO}://${CONTROLLER_IP}"
echo "[*] Detecting OS..."

OS="$(uname -s)"
ARCH="$(uname -m)"

echo "[*] Detected: $OS ($ARCH)"
echo "[*] Checking required dependencies..."
DEPS_MISSING=0

check_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo " ❌ Missing command: $1"
        DEPS_MISSING=1
    else
        echo " ✅ Found: $1"
    fi
}

check_cmd "curl"
check_cmd "sudo"

if [ "$OS" = "Linux" ]; then
    check_cmd "systemctl"

    # Memeriksa ketersediaan libssl untuk kebutuhan WAF
    if ! command -v openssl >/dev/null 2>&1 && ! ldconfig -p 2>/dev/null | grep -q "libssl"; then
        echo " ❌ Missing library: libssl (OpenSSL)"
        DEPS_MISSING=1
    else
        echo " ✅ Found: libssl (OpenSSL)"
    fi
fi

if [ $DEPS_MISSING -eq 1 ]; then
    echo ""
    echo "⚠️  Error: Beberapa dependensi sistem belum terinstall."
    echo "Silakan install terlebih dahulu. Contoh untuk Ubuntu/Debian:"
    echo "   sudo apt update && sudo apt install curl sudo systemd openssl -y"
    exit 1
fi
INSTALL_DIR="/opt/jarswaf"
echo "[*] Creating installation directory at $INSTALL_DIR..."
sudo mkdir -p "$INSTALL_DIR"

echo "[*] Downloading jarsWAF Agent binary dari Controller..."
# --fail so a 404/error response aborts instead of writing an error-page "binary".
sudo curl --fail --retry 3 -fsSL "${PROTO}://${CONTROLLER_IP}/bin/jarswaf-agent-${OS}-${ARCH}" -o "$INSTALL_DIR/jarswaf-agent"
sudo chmod +x "$INSTALL_DIR/jarswaf-agent"

echo "[*] Validating downloaded binary is not an error page (ELF check on Linux)..."
if [ "$OS" = "Linux" ] && ! sudo head -c 4 "$INSTALL_DIR/jarswaf-agent" | od -An -tx1 | grep -qi '7f 45 4c 46'; then
  echo "❌ Downloaded file is not a valid ELF binary — aborting. Check controller URL/archive."
  exit 1
fi

echo "[*] Generating Agent Configuration (config.toml)..."
# Write via a quoted heredoc so no interpolation/exec occurs on attacker-controlled values.
sudo tee "$INSTALL_DIR/config.toml" >/dev/null <<EOF
mode = "agent"
controller_url = "${PROTO}://${CONTROLLER_IP}"
port = 80
EOF

if [ "$OS" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
    echo "[*] Setting up systemd background service (running as non-root user)..."
    # Dedicated unprivileged user; CAP_NET_BIND_SERVICE granted ambiently so the agent
    # can bind 80/443 without ever running as root. `ponytail:` if ambient caps are
    # ignored on your systemd/kernel, setcap on the binary as a fallback.
    if ! id -u jarswaf &>/dev/null; then
        sudo useradd --system --no-create-home --shell /usr/sbin/nologin jarswaf 2>/dev/null || true
    fi
    sudo chown -R jarswaf:jarswaf "$INSTALL_DIR" 2>/dev/null || true

    sudo tee /etc/systemd/system/jarswaf-agent.service >/dev/null <<EOF
[Unit]
Description=jarsWAF Agent
After=network.target

[Service]
Type=simple
User=jarswaf
Group=jarswaf
ExecStart=$INSTALL_DIR/jarswaf-agent --config $INSTALL_DIR/config.toml
WorkingDirectory=$INSTALL_DIR
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable jarswaf-agent
    echo "[*] To install the jarswaf binary into the dashboard/bin directory of the controller, copy it manually."
    echo "[*] Service registered. Run 'sudo systemctl start jarswaf-agent' to begin proxying traffic."
else
    echo "[*] To start the agent manually, run:"
    echo "    $INSTALL_DIR/jarswaf-agent --config $INSTALL_DIR/config.toml"
fi

echo "================================================="
echo " ✅ jarsWAF Agent installation completed!"
echo "================================================="
