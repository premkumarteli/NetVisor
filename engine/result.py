from dataclasses import dataclass, field
from typing import Any, Dict, List
from .findings import Finding

@dataclass(frozen=True)
class EngineResult:
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
