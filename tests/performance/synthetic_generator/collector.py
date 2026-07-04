import numpy as np

class MetricsCollector:
    """Collects raw latency samples and evaluates statistical percentiles (P50/P95/P99) and errors."""
    
    def __init__(self):
        self.latencies = []
        self.error_count = 0

    def record_latency(self, duration: float):
        if duration > 0:
            self.latencies.append(duration)
        else:
            self.error_count += 1

    def compute_statistics(self, total_sent: int, elapsed_seconds: float) -> dict:
        if not self.latencies:
            return {
                "throughput": 0.0,
                "p50_ms": 0.0,
                "p95_ms": 0.0,
                "p99_ms": 0.0,
                "error_count": self.error_count
            }
            
        # Convert to milliseconds
        latencies_ms = np.array(self.latencies) * 1000.0
        
        return {
            "throughput": total_sent / elapsed_seconds if elapsed_seconds > 0 else 0.0,
            "p50_ms": float(np.percentile(latencies_ms, 50)),
            "p95_ms": float(np.percentile(latencies_ms, 95)),
            "p99_ms": float(np.percentile(latencies_ms, 99)),
            "error_count": self.error_count
        }
