import urllib.request
import urllib.error
import threading
import time
import random
import sys
from concurrent.futures import ThreadPoolExecutor

# Default WAF Target configuration
# If your WAF runs on a different port or address, you can change this
TARGET_URL = "http://localhost"
HOST_HEADER = "dev.azharmtq.my.id"

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
    "errors": 0        # Connection errors
}

lock = threading.Lock()
stop_testing = False

def send_request(url, type_name):
    global stop_testing
    if stop_testing:
        return
        
    req = urllib.request.Request(url)
    req.add_header("Host", HOST_HEADER)
    req.add_header("User-Agent", "jarsWAF-Stress-Tester/1.0")
    
    try:
        with urllib.request.urlopen(req, timeout=3.0) as response:
            status = response.getcode()
            with lock:
                stats["sent"] += 1
                if status == 200 or status == 302:
                    stats["success"] += 1
    except urllib.error.HTTPError as e:
        status = e.code
        with lock:
            stats["sent"] += 1
            if status == 403:
                stats["blocked"] += 1
            elif status == 429:
                stats["rate_limited"] += 1
            else:
                stats["errors"] += 1
    except Exception as e:
        with lock:
            stats["errors"] += 1

def worker_thread():
    while not stop_testing:
        # Choose a random traffic type:
        # 50% Normal traffic
        # 12.5% SQL Injection
        # 12.5% XSS
        # 12.5% LFI
        # 12.5% Rate Limit Triggers
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
        
        send_request(url, traffic_type)
        
        # Micro sleep to control throughput
        time.sleep(random.uniform(0.01, 0.1))

def print_stats():
    while not stop_testing:
        time.sleep(1.0)
        with lock:
            print(f"\r[Stress Test] Requests: {stats['sent']} | OK: {stats['success']} | Blocks (403): {stats['blocked']} | Rate-Limits (429): {stats['rate_limited']} | Errors: {stats['errors']}", end="")
            sys.stdout.flush()

if __name__ == "__main__":
    print("=========================================================")
    print("         jarsWAF Real-Time Stress Tester               ")
    print("=========================================================")
    print(f"Target URL : {TARGET_URL}")
    print(f"Host Header: {HOST_HEADER}")
    print("Press Ctrl+C to stop the test.")
    print("---------------------------------------------------------")
    
    # Run the stats printer thread
    printer = threading.Thread(target=print_stats, daemon=True)
    printer.start()
    
    # Use a ThreadPoolExecutor to simulate 16 concurrent users
    concurrency = 16
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        try:
            for _ in range(concurrency):
                executor.submit(worker_thread)
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nStopping stress test...")
            stop_testing = True
            print("Done!")
