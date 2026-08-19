from typing import Optional
from .models import DeviceProfile, Evidence
from .oui_detector import OUIDetector
from .hostname_detector import HostnameDetector
from .dhcp_detector import DHCPDetector
from .mdns_detector import MDNSDetector
from .ssdp_detector import SSDPDetector
from .active_prober import ActiveProber
from backend.engines.common.evidence import EvidenceTracker
from backend.engines.common.config import EngineConfig

class DevicePipeline:
    def __init__(self, config: EngineConfig = None) -> None:
        self.config = config if config is not None else EngineConfig()
        self.oui_detector = OUIDetector()
        self.hostname_detector = HostnameDetector()
        self.dhcp_detector = DHCPDetector()
        self.mdns_detector = MDNSDetector()
        self.ssdp_detector = SSDPDetector()

        # Build active prober ports map from configuration
        ports_dict = {
            port: ActiveProber.COMMON_PORTS.get(port, "Unknown Device")
            for port in self.config.active_prober_ports
        }
        self.active_prober = ActiveProber(ports_dict)

    def run(self, context: dict) -> DeviceProfile:
        ip = context.get("ip", "0.0.0.0")
        mac = context.get("mac")
        hostname = context.get("hostname")
        dhcp_fingerprint = context.get("dhcp_fingerprint")
        mdns_services = context.get("mdns_services")
        ssdp_services = context.get("ssdp_services")
        ssdp_friendly_name = context.get("ssdp_friendly_name")
        # Default active_probe to False per safety requirements
        active_probe_allowed = context.get("active_probe", False)

        tracker = EvidenceTracker(self.config.device_weights)


        # 1. Resolve OUI Hardware Vendor
        vendor = "Unknown"
        if mac:
            vendor = self.oui_detector.resolve_vendor(mac)
            if vendor != "Unknown":
                tracker.add_evidence("oui", vendor)

        # 2. Resolve Hostname
        resolved_hostname = "Unknown"
        if hostname:
            cleaned = self.hostname_detector.clean_hostname(hostname)
            if cleaned:
                resolved_hostname = cleaned
                tracker.add_evidence("hostname", resolved_hostname)

        # 3. Analyze DHCP
        dhcp_res = self.dhcp_detector.analyze(dhcp_fingerprint)
        if dhcp_res and dhcp_res.os_family != "Unknown":
            tracker.add_evidence("dhcp", dhcp_res.os_family)

        # 4. Analyze mDNS
        mdns_res = self.mdns_detector.analyze(mdns_services)
        if mdns_res and mdns_res.inferred_type:
            services_val = ", ".join(mdns_res.services)
            tracker.add_evidence("mdns", services_val)

        # 5. Analyze SSDP
        ssdp_res = self.ssdp_detector.analyze(ssdp_services, ssdp_friendly_name)
        if ssdp_res and ssdp_res.inferred_type:
            val = ssdp_res.friendly_name or (", ".join(ssdp_res.services) if ssdp_res.services else "UPnP")
            tracker.add_evidence("ssdp", val)

        # Priority Resolution for Device Type:
        # Priority order: DHCP / mDNS -> Hostname -> SSDP -> OUI -> Active Probing (as fallback)
        device_type = "Unknown"

        mdns_type = mdns_res.inferred_type if mdns_res else None
        ssdp_type = ssdp_res.inferred_type if ssdp_res else None
        hostname_type = self.hostname_detector.infer_device_type(resolved_hostname) if resolved_hostname != "Unknown" else "Unknown"
        os_family = dhcp_res.os_family if dhcp_res else "Unknown"

        # A. Evaluate specific consumer discovery channels first (mDNS / SSDP specific models)
        if mdns_type and mdns_type != "Unknown":
            device_type = mdns_type
        elif ssdp_type and ssdp_type in {"Roku / Smart TV", "Smart Speaker", "Chromecast / Smart TV"}:
            device_type = ssdp_type
        elif hostname_type and hostname_type != "Unknown":
            device_type = hostname_type
        elif ssdp_type and ssdp_type != "Unknown":
            device_type = ssdp_type

        # B. If still unknown, leverage DHCP OS Family combined with other hints
        if device_type == "Unknown" and os_family != "Unknown":
            if os_family == "Windows":
                device_type = "Windows Device"
            elif os_family == "Apple OS":
                device_type = "Mobile Phone"  # Default Apple OS to Mobile Phone unless refined
            elif os_family == "Linux":
                device_type = "Linux/Unix Device"  # Default Linux OS to generic Linux/Unix Device

        # C. Refine generic classifications using OUI or Hostname clues
        if device_type == "Linux/Unix Device":
            if hostname_type == "Mobile Phone":
                device_type = "Mobile Phone"  # Android is Linux-based
            elif hostname_type == "NAS / Storage":
                device_type = "NAS / Storage"  # Synology runs Linux
            elif vendor == "Synology":
                device_type = "NAS / Storage"
            elif vendor == "Raspberry Pi":
                device_type = "Linux/IoT Device"
        elif device_type == "Mobile Phone" and os_family == "Apple OS":
            if hostname_type == "Tablet":
                device_type = "Tablet"  # iPad

        # D. Quaternary tier: OUI Vendor Fallback markers
        if device_type == "Unknown" and vendor != "Unknown":
            from .constants import MOBILE_VENDOR_MARKERS
            vendor_lower = vendor.lower()
            if any(marker in vendor_lower for marker in MOBILE_VENDOR_MARKERS):
                device_type = "Mobile Phone"
            elif "vmware" in vendor_lower or "virtualbox" in vendor_lower or "hyper-v" in vendor_lower:
                device_type = "Virtual Machine"
            elif "raspberry" in vendor_lower:
                device_type = "Linux/IoT Device"
            elif "synology" in vendor_lower:
                device_type = "NAS / Storage"

        # E. Active Probing Fallback: Only connect if unclassified, confidence is low, and allowed
        if device_type == "Unknown" and tracker.total_confidence < self.config.active_probe_low_confidence_threshold and active_probe_allowed:
            probed_type = self.active_prober.probe(ip)
            if probed_type != "Unknown":
                device_type = probed_type
                tracker.add_evidence("active_probe", probed_type)

        return DeviceProfile(
            ip=ip,
            mac=mac,
            hostname=resolved_hostname,
            vendor=vendor,
            device_type=device_type,
            confidence=tracker.total_confidence,
            confidence_level=tracker.get_confidence_level(),
            evidence_sources=tracker.evidence_sources
        )
