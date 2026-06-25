from dataclasses import dataclass
from typing import Any, Dict, List

@dataclass(frozen=True)
class Evidence:
    source: str       # e.g., "oui", "hostname", "dhcp", "mdns", "ssdp", "dns_entropy"
    value: Any        # e.g., "VMware", 4.2
    weight: float     # e.g., 0.15, 0.40
    confidence: float = 1.0 # individual evidence confidence (defaults to 1.0)

class EvidenceTracker:
    def __init__(self, weights: Dict[str, float]) -> None:
        self.weights = weights
        self.evidence_sources: List[Evidence] = []

    def add_evidence(self, source: str, value: Any, confidence: float = 1.0) -> None:
        weight = self.weights.get(source, 0.0) * confidence
        self.evidence_sources.append(
            Evidence(source=source, value=value, weight=weight, confidence=confidence)
        )

    @property
    def total_confidence(self) -> float:
        total = sum(ev.weight for ev in self.evidence_sources)
        return min(1.0, round(total, 2))

    def get_confidence_level(self) -> str:
        score = self.total_confidence
        if score >= 0.85:
            return "high"
        elif score >= 0.50:
            return "medium"
        else:
            return "low"
