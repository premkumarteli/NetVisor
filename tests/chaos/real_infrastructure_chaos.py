import subprocess
import time
import httpx
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor

def run_server():
    """Start NetVisor Server in background."""
    print("Starting server for Real Infrastructure Chaos validation...")
    cmd = [os.path.join(".venv", "Scripts", "python"), "-m", "uvicorn", "backend.main:app", "--port", "8000"]
    env = os.environ.copy()
    env["MTLS_MODE"] = "disabled"
    env["NETVISOR_CHAOS_TESTING"] = "1"
    server_process = subprocess.Popen(cmd, env=env)
    return server_process

def test_scoped_chaos():
    server = run_server()
    # Wait for server to bind port
    time.sleep(5)
    
    url = "http://127.0.0.1:8000/api/v1/health/ready"
    
    # Verify baseline health is successful
    print("Verifying baseline health status...")
    r = httpx.get(url)
    print(f"Baseline Health Status: {r.status_code}")
    if r.status_code != 200:
        print("Error: Baseline health check failed. Ensure MySQL database is running.")
        server.terminate()
        server.wait()
        sys.exit(1)
        
    print("\n--- Verifying Isolated Request-Scoped Chaos ---")
    
    # We will trigger concurrent requests to ensure Request A (chaos) does not leak to Request B (normal)
    # Even if they run at the exact same time!
    
    results = {}
    
    def send_chaos_request():
        # Request A: Injects DB-Down failure
        try:
            res = httpx.get(url, headers={"X-Chaos-DB-Down": "1"}, timeout=5.0)
            results["chaos"] = (res.status_code, res.text)
        except Exception as e:
            results["chaos"] = (500, str(e))

    def send_normal_request():
        # Request B: Normal request, should succeed
        try:
            res = httpx.get(url, timeout=5.0)
            results["normal"] = (res.status_code, res.text)
        except Exception as e:
            results["normal"] = (500, str(e))

    # Run them concurrently in threads
    t_chaos = threading.Thread(target=send_chaos_request)
    t_normal = threading.Thread(target=send_normal_request)
    
    t_chaos.start()
    t_normal.start()
    
    t_chaos.join()
    t_normal.join()
    
    # Output outcomes
    chaos_status, chaos_text = results.get("chaos", (0, ""))
    normal_status, normal_text = results.get("normal", (0, ""))
    
    print(f"Request A (with X-Chaos-DB-Down: 1) Status: {chaos_status}")
    print(f"Request B (Normal) Status: {normal_status}")
    
    # Assertions
    # Request A must fail with 503 Service Unavailable since DB down is simulated
    # Request B must succeed with 200 OK
    passed = (chaos_status == 503) and (normal_status == 200)
    
    # 2. Test latency injection check
    print("\n--- Verifying Latency Injection Chaos ---")
    t_start = time.perf_counter()
    r_slow = httpx.get(url, headers={"X-Chaos-DB-Latency": "1.0"})
    duration = time.perf_counter() - t_start
    print(f"Request with 1.0s DB Latency header duration: {duration:.2f}s (Status: {r_slow.status_code})")
    
    latency_passed = duration >= 1.0
    
    print("\nTerminating server...")
    server.terminate()
    server.wait()
    
    if passed and latency_passed:
        print("\nSUCCESS: All request-scoped contextvars chaos assertions passed!")
        sys.exit(0)
    else:
        print("\nFAILURE: Chaos isolation test failed.")
        print(f"DB Down Test Passed: {passed}")
        print(f"DB Latency Test Passed: {latency_passed}")
        sys.exit(1)

if __name__ == "__main__":
    test_scoped_chaos()
