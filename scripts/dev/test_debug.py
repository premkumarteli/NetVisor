from backend.engines.registry import EngineRegistry
from backend.engines.threat.beaconing import BeaconingDetector
from statistics import mean, pstdev

original_analyze = BeaconingDetector.analyze

def custom_analyze(self, flow, observed_at):
    src_ip = flow.get("src_ip")
    dst_ip = flow.get("dst_ip")
    dst_port = flow.get("dst_port")
    key = (src_ip, dst_ip, dst_port, "beaconing")
    
    res = original_analyze(self, flow, observed_at)
    
    bucket = self.store._stores[key]
    if len(bucket) >= 5:
        timestamps = sorted([ts for ts in bucket])
        intervals = [
            (timestamps[idx] - timestamps[idx - 1]).total_seconds()
            for idx in range(1, len(timestamps))
        ]
        avg_interval = mean(intervals)
        interval_stdev = pstdev(intervals) if len(intervals) > 1 else 0.0
        cov = interval_stdev / avg_interval if avg_interval > 0 else 0.0
        print(f"\n[BeaconingDetector debug] at {observed_at}")
        print(f"  timestamps: {timestamps}")
        print(f"  intervals: {intervals}")
        print(f"  avg_interval: {avg_interval}")
        print(f"  interval_stdev: {interval_stdev}")
        print(f"  cov: {cov}")
        print(f"  cov_threshold: {self.config.beaconing_cov_threshold}")
        print(f"  condition 1 (5 <= avg <= 600): {5 <= avg_interval <= 600}")
        print(f"  condition 2 (cov <= thresh): {cov <= self.config.beaconing_cov_threshold}")
        print(f"  condition 3 (stdev <= 1.0): {interval_stdev <= 1.0}")
        print(f"  Result: {res}")
    return res

BeaconingDetector.analyze = custom_analyze

def debug():
    registry = EngineRegistry()
    target_ip = "10.0.0.10"
    
    for i in range(5):
        registry.analyze_selective({
            "src_ip": target_ip,
            "dst_ip": "8.8.8.8",
            "dst_port": 80,
            "protocol": "TCP",
            "last_seen": f"2026-06-13 12:00:{i*30:02d}"
        }, ["vpn", "threat", "risk"])

if __name__ == "__main__":
    debug()
