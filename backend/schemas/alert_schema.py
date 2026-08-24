from pydantic import BaseModel
from typing import Dict, Any, Optional

class AlertBase(BaseModel):
    device_ip: str
    severity: str
    risk_score: float
    breakdown: Dict[str, Any]
    organization_id: str
    alert_type: Optional[str] = "ANOMALY"
    message: str | None = None

class Alert(AlertBase):
    id: int
    timestamp: str
    resolved: bool = False

class RiskEventBase(BaseModel):
    organization_id: str
    device_id: str
    risk_type: str
    confidence: float = 1.0
    score: int
    evidence_json: Optional[Dict[str, Any]] = None

class RiskEvent(RiskEventBase):
    id: int
    timestamp: str

