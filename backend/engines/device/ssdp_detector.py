from typing import List, Optional
from .models import SSDPResult

class SSDPDetector:
    def analyze(self, services: Optional[List[str]], friendly_name: Optional[str]) -> Optional[SSDPResult]:
        if not services and not friendly_name:
            return None

        inferred_type = None
        # Check friendly name first for high specificity
        if friendly_name:
            fn_lower = friendly_name.lower()
            if "roku" in fn_lower:
                inferred_type = "Roku / Smart TV"
            elif "sonos" in fn_lower:
                inferred_type = "Smart Speaker"
            elif "chromecast" in fn_lower:
                inferred_type = "Chromecast / Smart TV"

        # Fall back to UPnP service type URIs
        if not inferred_type and services:
            for s in services:
                if "ZonePlayer" in s:
                    inferred_type = "Smart Speaker"
                    break
                elif "MediaRenderer" in s:
                    inferred_type = "Smart TV"
                    break

        return SSDPResult(services=services or [], friendly_name=friendly_name, inferred_type=inferred_type)
