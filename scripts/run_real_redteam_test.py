#!/usr/bin/env python3
"""
Orchestrator for 100% Real Live Red Team Cycle 5 Testing.
Spawns Backend Echo Server on 8080 & jarsWAF Release Binary on 8000.
Executes redteam_attack3_fresh.py and cleans up processes cleanly.
"""

import os
import subprocess
import sys
import time

def main():
    print("=== ORCHESTRATING 100% REAL LIVE JARSWAF RED TEAM TEST ===")
    
    # 1. Start Backend Echo Server on 8080
    backend_proc = subprocess.Popen(
        [sys.executable, "scripts/redteam_backend.py", "8080"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print("[1/4] Backend Echo Server started on port 8080 (PID: {})".format(backend_proc.pid))
    time.sleep(0.5)

    # 2. Start jarsWAF on port 8000
    waf_proc = subprocess.Popen(
        ["./target/release/jarswaf", "--config", "redteam.toml"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print("[2/4] jarsWAF Release Proxy started on port 8000 (PID: {})".format(waf_proc.pid))
    print("[3/4] Waiting 2 seconds for WAF initialization & listener binding...")
    time.sleep(2)

    try:
        # 3. Execute Attack Harness Live
        print("[4/4] Executing Red Team Cycle 5 Attack Harness Live...\n")
        res = subprocess.run([sys.executable, "scripts/redteam_attack3_fresh.py"], check=False)
        print(f"\n[ORCHESTRATOR] Harness process exited with code: {res.returncode}")
    finally:
        print("[CLEANUP] Terminating jarsWAF and Backend processes...")
        waf_proc.terminate()
        backend_proc.terminate()
        try:
            waf_proc.wait(timeout=2)
            backend_proc.wait(timeout=2)
        except Exception:
            waf_proc.kill()
            backend_proc.kill()
        print("=== LIVE TEST ORCHESTRATION COMPLETED CLEANLY ===")

if __name__ == "__main__":
    main()
