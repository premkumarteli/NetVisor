import threading
from collections import defaultdict
from datetime import datetime
import math
from typing import Any, Optional
from shared.engine import Finding, Severity
from .state import get_flow_field
from app.engines.common.config import EngineConfig

class DNSTunnelingDetector:
    def __init__(self, config: EngineConfig = None) -> None:
        self.config = config if config is not None else EngineConfig()
        # State: src_ip -> parent_domain -> {subdomain: last_seen_timestamp}
        self.dns_subdomain_counts = defaultdict(lambda: defaultdict(dict))
        self._lock = threading.RLock()

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counts = defaultdict(int)
        for char in text:
            counts[char] += 1
        entropy = 0.0
        length = len(text)
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def analyze(self, flow: Any, observed_at: datetime) -> Optional[Finding]:
        domain = str(get_flow_field(flow, "domain", "") or "").lower()
        src_ip = get_flow_field(flow, "src_ip")
        if not domain or not src_ip or domain.count(".") < 2:
            return None

        parts = domain.split(".")
        subdomain = parts[0]
        parent_domain = ".".join(parts[-2:])

        # 1. Entropy Check: Requires BOTH high entropy AND long label
        entropy = self._calculate_entropy(subdomain)
        if len(subdomain) > self.config.dns_tunneling_label_length and entropy > self.config.dns_tunneling_entropy_threshold:
            return Finding(
                engine="threat",
                finding_type="dns_tunneling",
                severity=Severity.CRITICAL,
                confidence=0.90,
                evidence=[f"DNS Tunneling Detected: High entropy domain {domain}"],
                timestamp=observed_at,
                target_ip=src_ip,
                details={
                    "src_ip": src_ip,
                    "domain": domain,
                    "subdomain": subdomain,
                    "entropy": round(entropy, 2),
                    "length": len(subdomain)
                }
            )

        # 2. Subdomain Bloom Check with TTL Pruning
        with self._lock:
            subdomain_dict = self.dns_subdomain_counts[src_ip][parent_domain]
            subdomain_dict[subdomain] = observed_at

            # Prune subdomains older than the TTL
            expired = [
                sub for sub, ts in subdomain_dict.items()
                if (observed_at - ts).total_seconds() > self.config.dns_tunneling_ttl
            ]
            for sub in expired:
                del subdomain_dict[sub]

            unique_count = len(subdomain_dict)
            
            # Prune empty keys to prevent memory leaks
            if not subdomain_dict:
                self.dns_subdomain_counts[src_ip].pop(parent_domain, None)
                if not self.dns_subdomain_counts[src_ip]:
                    self.dns_subdomain_counts.pop(src_ip, None)

        if unique_count > self.config.dns_tunneling_bloom_threshold:
            return Finding(
                engine="threat",
                finding_type="dns_tunneling",
                severity=Severity.CRITICAL,
                confidence=0.90,
                evidence=[f"DNS Tunneling Detected: {unique_count} unique subdomains queried for {parent_domain}"],
                timestamp=observed_at,
                target_ip=src_ip,
                details={
                    "src_ip": src_ip,
                    "parent_domain": parent_domain,
                    "unique_subdomain_count": unique_count
                }
            )
        return None

    def clear(self) -> None:
        """Clear all subdomain counts thread-safely."""
        with self._lock:
            self.dns_subdomain_counts.clear()

