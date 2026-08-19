from typing import Optional
from .models import DHCPResult

class DHCPDetector:
    # Standard Option 55 Fingerprints mapping to OS Family
    FINGERPRINTS = {
        "1,3,6,15,31,33,43,44,46,121,249,252": "Windows",
        "1,121,3,6,15,119,252,95,44,46": "Apple OS",
        "1,3,6,15,26,28,51,58,59": "Linux"
    }

    def analyze(self, fingerprint: Optional[str]) -> Optional[DHCPResult]:
        if not fingerprint:
            return None
        cleaned = str(fingerprint).strip().replace(" ", "")
        os_family = self.FINGERPRINTS.get(cleaned, "Unknown")
        return DHCPResult(fingerprint=cleaned, os_family=os_family)
