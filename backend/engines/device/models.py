from dataclasses import dataclass, field
from typing import List, Optional
from backend.engines.common.evidence import Evidence


@dataclass(frozen=True)
class MDNSResult:
    services: List[str]
    inferred_type: Optional[str] = None
    confidence: float = 1.0

@dataclass(frozen=True)
class DHCPResult:
    fingerprint: str
    os_family: Optional[str] = None

@dataclass(frozen=True)
class SSDPResult:
    services: List[str]
    friendly_name: Optional[str] = None
    inferred_type: Optional[str] = None

@dataclass
class DeviceProfile:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: str = "Unknown"
    device_type: str = "Unknown"
    confidence: float = 0.0
    confidence_level: str = "low"
    evidence_sources: List[Evidence] = field(default_factory=list)
