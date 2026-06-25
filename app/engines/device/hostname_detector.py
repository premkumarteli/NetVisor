from typing import Optional
from .constants import HOSTNAME_TYPE_HINTS

class HostnameDetector:
    def clean_hostname(self, hostname: Optional[str]) -> Optional[str]:
        if not hostname:
            return None
        cleaned = str(hostname).strip().strip(".")
        if not cleaned or cleaned in {"*", "Unknown", "Unknown-Device"}:
            return None
        if cleaned.lower().endswith(".local"):
            cleaned = cleaned[:-6]
        return cleaned or None

    def infer_device_type(self, hostname: Optional[str]) -> str:
        cleaned = self.clean_hostname(hostname)
        if not cleaned:
            return "Unknown"
        normalized = cleaned.lower()
        for marker, device_type in HOSTNAME_TYPE_HINTS.items():
            if marker in normalized:
                return device_type
        return "Unknown"
