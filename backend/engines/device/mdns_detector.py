from typing import List, Optional
from .models import MDNSResult

class MDNSDetector:
    def analyze(self, services: Optional[List[str]]) -> Optional[MDNSResult]:
        if not services:
            return None

        inferred_type = None
        for service in services:
            service_lower = service.lower()
            if "_googlecast._tcp.local" in service_lower:
                inferred_type = "Chromecast / Smart TV"
                break
            elif "_apple-mobdev2._tcp.local" in service_lower:
                inferred_type = "Mobile Phone"
                break
            elif "_airplay._tcp.local" in service_lower or "_raop._tcp.local" in service_lower:
                inferred_type = "Smart TV"
                break

        return MDNSResult(services=services, inferred_type=inferred_type)
