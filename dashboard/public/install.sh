#!/bin/bash
set -e

echo "================================================="
echo " 🛡️ jarsWAF Agent Installation (Linux / macOS)"
echo "================================================="

if [ -z "$CONTROLLER_IP" ]; then
  echo "Error: CONTROLLER_IP environment variable not set."
  echo "Usage: curl -sSL http://<IP>:8080/install.sh | CONTROLLER_IP=<IP>:8080 bash"
  exit 1
fi

echo "[*] Connecting to jarsWAF Central Controller at: $CONTROLLER_IP"
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
sudo curl -sSL "http://$CONTROLLER_IP/bin/jarswaf-agent-$OS-$ARCH" -o "$INSTALL_DIR/jarswaf-agent"
sudo chmod +x "$INSTALL_DIR/jarswaf-agent"

echo "[*] Generating Agent Configuration (config.toml)..."
sudo bash -c "cat <<EOF > $INSTALL_DIR/config.toml
mode = \"agent\"
controller_url = \"http://$CONTROLLER_IP\"
port = 80
EOF"

if [ "$OS" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
    echo "[*] Setting up systemd background service..."
    sudo bash -c "cat <<EOF > /etc/systemd/system/jarswaf-agent.service
[Unit]
Description=jarsWAF Agent
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/jarswaf-agent --config $INSTALL_DIR/config.toml
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF"
    sudo systemctl daemon-reload
    sudo systemctl enable jarswaf-agent
    echo "[*] Service registered. Run 'sudo systemctl start jarswaf-agent' to begin proxying traffic."
else
    echo "[*] To start the agent manually, run:"
    echo "    sudo $INSTALL_DIR/jarswaf-agent --config $INSTALL_DIR/config.toml"
fi

echo "================================================="
echo " ✅ jarsWAF Agent installation completed!"
echo "================================================="
