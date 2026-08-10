from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from .severity import Severity

@dataclass(frozen=True)
class Finding:
    engine: str
    finding_type: str
    severity: Severity
    confidence: float
    evidence: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ttl: int = 300
    target_ip: Optional[str] = None
    target_mac: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
