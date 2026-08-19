from dataclasses import dataclass, field
from typing import List
from engine import Finding

@dataclass
class AnalysisModel:
    target_ip: str
    risk_score: int = 0
    severity: str = "INFO"
    active_attack_types: List[str] = field(default_factory=list)
    mitre_ids: List[str] = field(default_factory=list)
    raw_findings: List[Finding] = field(default_factory=list)
