from typing import Dict, List, Set
from app.core.config import settings

class EngineConfig:
    def __init__(self) -> None:
        # Device Engine Configuration
        self.device_weights: Dict[str, float] = {
            "dhcp": float(getattr(settings, "NETVISOR_DEVICE_WEIGHT_DHCP", 0.40)),
            "mdns": float(getattr(settings, "NETVISOR_DEVICE_WEIGHT_MDNS", 0.20)),
            "ssdp": float(getattr(settings, "NETVISOR_DEVICE_WEIGHT_SSDP", 0.15)),
            "oui": float(getattr(settings, "NETVISOR_DEVICE_WEIGHT_OUI", 0.15)),
            "hostname": float(getattr(settings, "NETVISOR_DEVICE_WEIGHT_HOSTNAME", 0.10)),
            "active_probe": float(getattr(settings, "NETVISOR_DEVICE_WEIGHT_ACTIVE_PROBE", 0.15)),
        }
        self.active_prober_ports: List[int] = list(getattr(settings, "NETVISOR_ACTIVE_PROBER_PORTS", [8008, 80, 443, 22, 8060, 9100, 502, 3000]))
        self.active_probe_low_confidence_threshold: float = float(getattr(settings, "NETVISOR_ACTIVE_PROBE_CONF_THRESHOLD", 0.50))

        # Threat Engine Configuration
        self.port_scan_threshold: int = int(getattr(settings, "NETVISOR_PORT_SCAN_PORTS_THRESHOLD", 10))
        self.port_scan_window: int = int(getattr(settings, "NETVISOR_PORT_SCAN_WINDOW_SECONDS", 10))

        self.brute_force_attempts_threshold: int = int(getattr(settings, "NETVISOR_BRUTE_FORCE_ATTEMPTS_THRESHOLD", 15))
        self.brute_force_window: int = int(getattr(settings, "NETVISOR_BRUTE_FORCE_WINDOW_SECONDS", 60))
        self.brute_force_duration_threshold: float = float(getattr(settings, "NETVISOR_BRUTE_FORCE_DURATION_THRESHOLD", 1.0))
        self.brute_force_bytes_threshold: int = int(getattr(settings, "NETVISOR_BRUTE_FORCE_BYTES_THRESHOLD", 500))
        self.brute_force_ports: Set[int] = set(getattr(settings, "NETVISOR_BRUTE_FORCE_PORTS", {22, 3389, 445, 80, 443}))

        self.beaconing_min_events: int = int(getattr(settings, "NETVISOR_BEACONING_MIN_EVENTS", 5))
        self.beaconing_window: int = int(getattr(settings, "NETVISOR_BEACONING_WINDOW_SECONDS", 1800))
        self.beaconing_cov_threshold: float = float(getattr(settings, "NETVISOR_BEACONING_COV_THRESHOLD", 0.1))

        self.dns_tunneling_entropy_threshold: float = float(getattr(settings, "NETVISOR_DNS_TUNNELING_ENTROPY_THRESHOLD", 3.8))
        self.dns_tunneling_label_length: int = int(getattr(settings, "NETVISOR_DNS_TUNNELING_LABEL_LENGTH", 15))
        self.dns_tunneling_bloom_threshold: int = int(getattr(settings, "NETVISOR_DNS_TUNNELING_BLOOM_THRESHOLD", 50))
        self.dns_tunneling_ttl: int = int(getattr(settings, "NETVISOR_DNS_TUNNELING_TTL_SECONDS", 3600))

        self.large_upload_threshold: int = int(getattr(settings, "NETVISOR_LARGE_UPLOAD_THRESHOLD_BYTES", 5000000))

        # Risk Engine Configuration
        self.risk_decay_half_life: float = float(getattr(settings, "NETVISOR_RISK_DECAY_HALF_LIFE", 300.0))
        self.risk_suppression_window: float = float(getattr(settings, "NETVISOR_RISK_SUPPRESSION_WINDOW", 60.0))

        # VPN Engine Configuration
        self.vpn_weights: Dict[str, float] = {
            "asn": float(getattr(settings, "NETVISOR_VPN_WEIGHT_ASN", 0.40)),
            "wireguard": float(getattr(settings, "NETVISOR_VPN_WEIGHT_WIREGUARD", 0.35)),
            "tls": float(getattr(settings, "NETVISOR_VPN_WEIGHT_TLS", 0.20)),
            "openvpn": float(getattr(settings, "NETVISOR_VPN_WEIGHT_OPENVPN", 0.50)),
            "tor": float(getattr(settings, "NETVISOR_VPN_WEIGHT_TOR", 0.80)),
        }
        self.vpn_threshold: float = float(getattr(settings, "NETVISOR_VPN_THRESHOLD", 0.50))


