"""Safe load test — hits health + metrics endpoints on the live server.
No destructive operations. Run while the server is up."""
import sys
import time
import statistics
import urllib.request
import urllib.error
import concurrent.futures

URLS = [
    "http://127.0.0.1:8000/api/v1/system/status",
    "http://127.0.0.1:8000/metrics",
]

def fetch_one(url):
    start = time.perf_counter()
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=5)
        elapsed = (time.perf_counter() - start) * 1000
        return resp.status, elapsed, None
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - start) * 1000
        return e.code, elapsed, str(e)
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return 0, elapsed, str(e)

def run_load_test(duration_sec=10, concurrency=20):
    print(f"Safe load test: {concurrency} threads, {duration_sec}s duration")
    print(f"Target: {URLS[0]}\n")

    latencies = []
    errors = 0
    status_codes = {}
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        while time.time() - start < duration_sec:
            futures = [pool.submit(fetch_one, url % {}) for url in URLS for _ in range(concurrency // len(URLS))]
            for f in concurrent.futures.as_completed(futures):
                status, elapsed_ms, err = f.result()
                latencies.append(elapsed_ms)
                status_codes[status] = status_codes.get(status, 0) + 1
                if err:
                    errors += 1

    total_requests = len(latencies)
    elapsed = time.time() - start

    if latencies:
        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.50)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]
    else:
        p50 = p95 = p99 = 0

    print("=== Safe Load Test Results ===")
    print(f"Duration:            {elapsed:.2f}s")
    print(f"Total Requests:      {total_requests:,}")
    print(f"Requests/sec:        {total_requests / elapsed:.1f}")
    print(f"P50 Latency:         {p50:.2f} ms")
    print(f"P95 Latency:         {p95:.2f} ms")
    print(f"P99 Latency:         {p99:.2f} ms")
    print(f"Errors:              {errors}")
    print(f"Status Codes:        {status_codes}")
    print(f"Avg Latency:         {statistics.mean(latencies):.2f} ms" if latencies else "")

if __name__ == "__main__":
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    concurrency = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    run_load_test(duration, concurrency)
