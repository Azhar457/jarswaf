#!/bin/bash
echo "==================================================="
echo "  Aegis WAF Development Launcher (Unix/macOS)"
echo "==================================================="
echo

# Handler to terminate all child processes on exit
cleanup() {
    echo
    echo "Stopping Aegis WAF processes..."
    kill "$PID_CONTROLLER" "$PID_AGENT" "$PID_VITE" 2>/dev/null
    exit
}
trap cleanup SIGINT SIGTERM

echo "Starting WAF Controller..."
cargo run -- controller &
PID_CONTROLLER=$!

sleep 2

echo "Starting WAF Agent (connecting to Controller)..."
cargo run -- agent --controller http://localhost:8080 &
PID_AGENT=$!

echo "Starting Dashboard Vite Dev Server..."
cd dashboard && npm run dev &
PID_VITE=$!
cd ..

echo
echo "All processes started!"
echo "Dashboard UI available at: http://localhost:5173/"
echo "Controller API available at: http://localhost:8080/"
echo "Press Ctrl+C to terminate all processes."
echo "==================================================="

# Keep the script running to monitor background processes
wait
