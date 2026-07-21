import urllib.request
import urllib.error
import threading
import time
import random
import sys
from concurrent.futures import ThreadPoolExecutor

# Default WAF Target configuration
# If your WAF runs on a different port or address, you can change this
TARGET_URL = "http://127.0.0.1:8080"
HOST_HEADER = "test.jarswafwaf.demo"

# Payload groups to simulate different events
PAYLOADS = {
    "normal": [
        "/",
        "/about",
        "/contact",
        "/products?category=security",
        "/blog/introducing-jarswaf"
    ],
    "sqli": [
        "/?id=1%20OR%201=1",
        "/?q=admin%27%20UNION%20SELECT%20null,username,password%20FROM%20users--",
        "/api/search?term=%27%20OR%20%27x%27=%27x"
    ],
    "xss": [
        "/?comment=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
        "/submit?msg=%3Cimg%20src=x%20onerror=alert(1)%3E",
        "/feedback?text=%3Csvg%20onload=javascript:alert(1)%3E"
    ],
    "lfi": [
        "/?file=../../../../etc/passwd",
        "/download?path=..\\..\\..\\windows\\win.ini",
        "/view?page=../../boot.ini"
    ],
    "rate_limit": [
        "/login",
        "/api/auth/token"
    ]
}

stats = {
    "sent": 0,
    "success": 0,      # Status 200/300
    "blocked": 0,      # Status 403 (WAF rule blocks)
    "rate_limited": 0, # Status 429 (Rate limiting blocks)
    "errors": 0,       # Connection errors
    "latencies": []    # Request latencies in ms
}

lock = threading.Lock()
stop_testing = False

def send_request(url, traffic_type, scenario="normal"):
    global stop_testing
    if stop_testing:
        return
        
    req = urllib.request.Request(url)
    req.add_header("Host", HOST_HEADER)
    req.add_header("User-Agent", "jarsWAF-Stress-Tester/1.0")
    
    if scenario == "normal":
        # Random headers
        for i in range(10):
            req.add_header(f"X-Random-Header-{random.randint(1, 1000)}", f"Value-{random.randint(1, 1000)}")
    elif scenario == "worst-case":
        # Identical/Predictable headers to test hash collision resistance (HashDoS simulation)
        for i in range(50):
            req.add_header(f"X-Collision-Header-{i}", f"Collision-Value-{i}")
    elif scenario == "control":
        pass # No extra headers, baseline testing
    
    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=3.0) as response:
            status = response.getcode()
            lat = (time.time() - start_time) * 1000
            with lock:
                stats["sent"] += 1
                stats["latencies"].append(lat)
                if status == 200 or status == 302:
                    stats["success"] += 1
    except urllib.error.HTTPError as e:
        status = e.code
        lat = (time.time() - start_time) * 1000
        with lock:
            stats["sent"] += 1
            stats["latencies"].append(lat)
            if status == 403:
                stats["blocked"] += 1
            elif status == 429:
                stats["rate_limited"] += 1
            elif status in (404, 405):
                stats["success"] += 1  # WAF passed request
            else:
                stats["errors"] += 1
    except Exception as e:
        with lock:
            stats["errors"] += 1

def worker_thread(scenario):
    while not stop_testing:
        r = random.random()
        if r < 0.50:
            traffic_type = "normal"
        elif r < 0.625:
            traffic_type = "sqli"
        elif r < 0.75:
            traffic_type = "xss"
        elif r < 0.875:
            traffic_type = "lfi"
        else:
            traffic_type = "rate_limit"

        path = random.choice(PAYLOADS[traffic_type])
        url = f"{TARGET_URL.rstrip('/')}{path}"
        
        send_request(url, traffic_type, scenario)
        
        # Reduced sleep for higher load
        time.sleep(random.uniform(0.001, 0.01))

def print_stats():
    while not stop_testing:
        time.sleep(1.0)
        with lock:
            print(f"\r[Stress Test] Requests: {stats['sent']} | OK: {stats['success']} | Blocks (403): {stats['blocked']} | Rate-Limits (429): {stats['rate_limited']} | Errors: {stats['errors']}", end="")
            sys.stdout.flush()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='jarsWAF Stress Tester')
    parser.add_argument('--scenario', type=str, choices=['normal', 'worst-case', 'control'], default='normal', help='Scenario to run')
    args = parser.parse_args()

    print("=========================================================")
    print("         jarsWAF Real-Time Stress Tester               ")
    print("=========================================================")
    print(f"Target URL : {TARGET_URL}")
    print(f"Host Header: {HOST_HEADER}")
    print(f"Scenario   : {args.scenario}")
    print("Press Ctrl+C to stop the test.")
    print("---------------------------------------------------------")
    
    printer = threading.Thread(target=print_stats, daemon=True)
    printer.start()
    
    concurrency = 16
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        try:
            for _ in range(concurrency):
                executor.submit(worker_thread, args.scenario)
            
            # Run test until we hit 10000 requests
            while True:
                time.sleep(0.5)
                with lock:
                    if stats["sent"] >= 10000:
                        stop_testing = True
                        break
        except KeyboardInterrupt:
            stop_testing = True
    
    print(f"\nDone! Processed {stats['sent']} requests in scenario '{args.scenario}'")
    if stats["latencies"]:
        sorted_lats = sorted(stats["latencies"])
        p95_idx = int(len(sorted_lats) * 0.95)
        p95 = sorted_lats[p95_idx]
        print(f"P95 Latency: {p95:.2f} ms")
