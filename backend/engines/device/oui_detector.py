from typing import Optional
from .constants import OUI_VENDOR_PREFIXES

class OUIDetector:
    def resolve_vendor(self, mac: Optional[str]) -> str:
        if not mac:
            return "Unknown"
        normalized = str(mac).replace("-", ":").upper()
        parts = [part for part in normalized.split(":") if part]
        if len(parts) < 3:
            return "Unknown"
        prefix = ":".join(parts[:3])
        return OUI_VENDOR_PREFIXES.get(prefix, "Unknown")
