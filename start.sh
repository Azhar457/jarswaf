#!/bin/bash
echo "==================================================="
echo "  jarsWAF Development Launcher (Unix/macOS)"
echo "==================================================="
echo

# Handler to terminate all child processes on exit
cleanup() {
    echo
    echo "Stopping jarsWAF processes..."
    kill "$PID_CONTROLLER" "$PID_AGENT" "$PID_VITE" 2>/dev/null
    exit
}
trap cleanup SIGINT SIGTERM

# No database setup needed for SQLite! WAF Controller initializes database automatically.

echo
echo "Step 3: Starting WAF Controller..."
cargo run --bin controller -- --port 8080 &
PID_CONTROLLER=$!

sleep 2

echo "Step 4: Starting WAF Agent (connecting to Controller)..."
cargo run --bin agent -- --controller http://localhost:8080 &
PID_AGENT=$!

echo "Step 5: Starting Dashboard Vite Dev Server..."
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
