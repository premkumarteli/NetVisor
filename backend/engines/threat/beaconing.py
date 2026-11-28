from datetime import datetime
import math
from typing import Any, Iterable, Optional, Tuple
from engine import Finding, Severity
from .state import SlidingWindowStore, get_flow_field
from backend.engines.common.config import EngineConfig


def welford_online_variance(intervals: Iterable[float]) -> Tuple[float, float, float]:
    """Computes mean, population standard deviation, and coefficient of variation
    in a single pass with O(1) space using Welford's algorithm.
    """
    count = 0
    mean_val = 0.0
    m2 = 0.0

    for x in intervals:
        count += 1
        delta = x - mean_val
        mean_val += delta / count
        delta2 = x - mean_val
        m2 += delta * delta2

    if count < 1:
        return 0.0, 0.0, 0.0

    variance = m2 / count
    stdev = math.sqrt(variance)
    cov = (stdev / mean_val) if mean_val > 0 else 0.0
    return mean_val, stdev, cov


class BeaconingDetector:
    def __init__(self, store: SlidingWindowStore, config: EngineConfig = None) -> None:
        self.store = store
        self.config = config if config is not None else EngineConfig()

    def analyze(self, flow: Any, observed_at: datetime) -> Optional[Finding]:
        src_ip = get_flow_field(flow, "src_ip")
        dst_ip = get_flow_field(flow, "dst_ip")
        dst_port = get_flow_field(flow, "dst_port")
        if dst_port is not None:
            try:
                dst_port = int(dst_port)
            except (ValueError, TypeError):
                dst_port = 0
        else:
            dst_port = 0

        if not src_ip or not dst_ip:
            return None

        key = (src_ip, dst_ip, dst_port, "beaconing")

        # Record timestamp to sliding window
        self.store.add(key, observed_at)

        # Retrieve and prune sliding window (configured threshold)
        bucket = self.store.get_and_prune(key, observed_at, self.config.beaconing_window)

        if len(bucket) < self.config.beaconing_min_events:
            return None

        # Sort timestamps and compute intervals using Welford's single-pass online variance
        timestamps = sorted([ts for ts in bucket])

        count = 0
        mean_val = 0.0
        m2 = 0.0
        for idx in range(1, len(timestamps)):
            x = (timestamps[idx] - timestamps[idx - 1]).total_seconds()
            count += 1
            delta = x - mean_val
            mean_val += delta / count
            delta2 = x - mean_val
            m2 += delta * delta2

        if count < 1:
            return None

        avg_interval = mean_val
        interval_stdev = math.sqrt(m2 / count)
        cov = (interval_stdev / avg_interval) if avg_interval > 0 else 0.0

        # Check coefficient of variation matches low variance threshold (with 1s jitter tolerance)
        if 5 <= avg_interval <= 600 and (cov <= self.config.beaconing_cov_threshold or interval_stdev <= 1.0):
            return Finding(
                engine="threat",
                finding_type="beaconing",
                severity=Severity.HIGH,
                confidence=0.90,
                evidence=[f"Possible C2 Beaconing: periodic connections with interval of {round(avg_interval, 1)}s and low variance"],
                timestamp=observed_at,
                target_ip=src_ip,
                details={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "average_interval_seconds": round(avg_interval, 2),
                    "interval_stdev": round(interval_stdev, 2),
                    "cov": round(cov, 3)
                }
            )
        return None
