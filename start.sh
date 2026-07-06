#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "==================================================="
echo "  jarsWAF Development Launcher"
echo "==================================================="
echo

cleanup() {
    echo
    echo "Stopping jarsWAF processes..."
    kill "$PID_CNTR" "$PID_AGENT" "$PID_VITE" 2>/dev/null || true
    exit
}
trap cleanup SIGINT SIGTERM

# Check for config
CONFIG="config.standalone.toml"
[ -f "$CONFIG" ] || { echo "Missing $CONFIG"; exit 1; }

echo "Step 1: Starting Controller (API server)..."
cargo run --bin controller -- --port 8080 &
PID_CNTR=$!

sleep 3

echo "Step 2: Starting Agent (WAF proxy)..."
cargo run --bin agent -- -c "$CONFIG" &
PID_AGENT=$!

sleep 2

echo "Step 3: Starting Dashboard (Vite dev server)..."
cd dashboard && npm run dev &
PID_VITE=$!
cd "$SCRIPT_DIR"

echo
echo "==================================================="
echo "  UI → http://localhost:5173/"
echo "  API → http://localhost:8080/"
echo "  Ctrl+C to stop all"
echo "==================================================="

wait
