"""Tests for device engine sub-detectors: OUI, mDNS, DHCP, SSDP, and pipeline integration."""
import pytest
from backend.engines.device.oui_detector import OUIDetector
from backend.engines.device.mdns_detector import MDNSDetector
from backend.engines.device.dhcp_detector import DHCPDetector
from backend.engines.device.ssdp_detector import SSDPDetector
from backend.engines.device.hostname_detector import HostnameDetector
from backend.engines.device.pipeline import DevicePipeline
from backend.engines.device.models import DeviceProfile
from backend.engines.common.config import EngineConfig


# ── OUI Detector ─────────────────────────────────────────────────────

class TestOUIDetector:
    def setup_method(self):
        self.detector = OUIDetector()

    def test_known_vendor_apple(self):
        assert self.detector.resolve_vendor("28:6A:BA:AA:BB:CC") == "Apple"

    def test_known_vendor_vmware(self):
        assert self.detector.resolve_vendor("00-50-56-12-34-56") == "VMware"

    def test_known_vendor_raspberry_pi(self):
        assert self.detector.resolve_vendor("DC:A6:32:AA:BB:CC") == "Raspberry Pi"

    def test_known_vendor_samsung(self):
        assert self.detector.resolve_vendor("18:65:90:AA:BB:CC") == "Samsung"

    def test_known_vendor_xiaomi(self):
        assert self.detector.resolve_vendor("64:CC:2E:AA:BB:CC") == "Xiaomi"

    def test_known_vendor_ubiquiti(self):
        assert self.detector.resolve_vendor("D8:3A:DD:AA:BB:CC") == "Ubiquiti"

    def test_known_vendor_synology(self):
        assert self.detector.resolve_vendor("00:11:32:AA:BB:CC") == "Synology"

    def test_known_vendor_hyper_v(self):
        assert self.detector.resolve_vendor("00:15:5D:AA:BB:CC") == "Microsoft Hyper-V"

    def test_known_vendor_virtualbox(self):
        assert self.detector.resolve_vendor("08:00:27:AA:BB:CC") == "Oracle VirtualBox"

    def test_unknown_vendor(self):
        assert self.detector.resolve_vendor("FF:FF:FF:AA:BB:CC") == "Unknown"

    def test_empty_mac(self):
        assert self.detector.resolve_vendor("") == "Unknown"

    def test_none_mac(self):
        assert self.detector.resolve_vendor(None) == "Unknown"

    def test_short_mac(self):
        assert self.detector.resolve_vendor("AA:BB") == "Unknown"

    def test_dash_separated_mac(self):
        assert self.detector.resolve_vendor("00-50-56-AA-BB-CC") == "VMware"

    def test_uppercase_insensitive(self):
        assert self.detector.resolve_vendor("28:6a:ba:aa:bb:cc") == "Apple"


# ── mDNS Detector ────────────────────────────────────────────────────

class TestMDNSDetector:
    def setup_method(self):
        self.detector = MDNSDetector()

    def test_chromecast(self):
        result = self.detector.analyze(["_googlecast._tcp.local"])
        assert result is not None
        assert result.inferred_type == "Chromecast / Smart TV"

    def test_apple_mobdev(self):
        result = self.detector.analyze(["_apple-mobdev2._tcp.local"])
        assert result is not None
        assert result.inferred_type == "Mobile Phone"

    def test_airplay(self):
        result = self.detector.analyze(["_airplay._tcp.local"])
        assert result is not None
        assert result.inferred_type == "Smart TV"

    def test_raop(self):
        result = self.detector.analyze(["_raop._tcp.local"])
        assert result is not None
        assert result.inferred_type == "Smart TV"

    def test_multiple_services_chromecast_wins(self):
        result = self.detector.analyze([
            "_http._tcp.local",
            "_googlecast._tcp.local",
            "_airplay._tcp.local",
        ])
        assert result.inferred_type == "Chromecast / Smart TV"

    def test_unknown_service(self):
        result = self.detector.analyze(["_http._tcp.local"])
        assert result is not None
        assert result.inferred_type is None

    def test_empty_services(self):
        assert self.detector.analyze([]) is None

    def test_none_services(self):
        assert self.detector.analyze(None) is None

    def test_services_list_preserved(self):
        result = self.detector.analyze(["_googlecast._tcp.local", "_http._tcp.local"])
        assert result.services == ["_googlecast._tcp.local", "_http._tcp.local"]

    def test_case_insensitive(self):
        result = self.detector.analyze(["_GOOGLECAST._TCP.LOCAL"])
        assert result.inferred_type == "Chromecast / Smart TV"


# ── DHCP Detector ────────────────────────────────────────────────────

class TestDHCPDetector:
    def setup_method(self):
        self.detector = DHCPDetector()

    def test_windows_fingerprint(self):
        result = self.detector.analyze("1,3,6,15,31,33,43,44,46,121,249,252")
        assert result.os_family == "Windows"

    def test_apple_fingerprint(self):
        result = self.detector.analyze("1,121,3,6,15,119,252,95,44,46")
        assert result.os_family == "Apple OS"

    def test_linux_fingerprint(self):
        result = self.detector.analyze("1,3,6,15,26,28,51,58,59")
        assert result.os_family == "Linux"

    def test_unknown_fingerprint(self):
        result = self.detector.analyze("1,2,3")
        assert result.os_family == "Unknown"

    def test_whitespace_stripped(self):
        result = self.detector.analyze(" 1 , 3 , 6 , 15 , 26 , 28 , 51 , 58 , 59 ")
        assert result.os_family == "Linux"

    def test_empty_fingerprint(self):
        assert self.detector.analyze("") is None

    def test_none_fingerprint(self):
        assert self.detector.analyze(None) is None

    def test_fingerprint_stored_cleaned(self):
        result = self.detector.analyze(" 1,3,6,15,26,28,51,58,59 ")
        assert result.fingerprint == "1,3,6,15,26,28,51,58,59"


# ── SSDP Detector ────────────────────────────────────────────────────

class TestSSDPDetector:
    def setup_method(self):
        self.detector = SSDPDetector()

    def test_roku_friendly_name(self):
        result = self.detector.analyze([], "Roku Express")
        assert result.inferred_type == "Roku / Smart TV"

    def test_sonos_friendly_name(self):
        result = self.detector.analyze([], "Sonos One")
        assert result.inferred_type == "Smart Speaker"

    def test_chromecast_friendly_name(self):
        result = self.detector.analyze([], "Chromecast")
        assert result.inferred_type == "Chromecast / Smart TV"

    def test_zoneplayer_service(self):
        result = self.detector.analyze(["urn:schemas-upnp-org:service:ZonePlayer:1"], None)
        assert result.inferred_type == "Smart Speaker"

    def test_mediarenderer_service(self):
        result = self.detector.analyze(["urn:schemas-upnp-org:device:MediaRenderer:1"], None)
        assert result.inferred_type == "Smart TV"

    def test_friendly_name_takes_priority(self):
        result = self.detector.analyze(
            ["urn:schemas-upnp-org:device:MediaRenderer:1"],
            "Roku Streaming Stick"
        )
        assert result.inferred_type == "Roku / Smart TV"

    def test_unknown_service_and_name(self):
        result = self.detector.analyze(["urn:schemas-upnp-org:device:Basic:1"], "Generic Device")
        assert result.inferred_type is None

    def test_empty_services_and_none_name(self):
        result = self.detector.analyze([], None)
        assert result is None

    def test_none_services_and_none_name(self):
        assert self.detector.analyze(None, None) is None

    def test_services_preserved(self):
        result = self.detector.analyze(["svc1", "svc2"], "Roku")
        assert result.services == ["svc1", "svc2"]
        assert result.friendly_name == "Roku"

    def test_case_insensitive_friendly_name(self):
        result = self.detector.analyze([], "SONOS speaker")
        assert result.inferred_type == "Smart Speaker"


# ── Pipeline Integration ─────────────────────────────────────────────

class TestDevicePipeline:
    def setup_method(self):
        self.pipeline = DevicePipeline()

    def test_oui_only(self):
        profile = self.pipeline.run({"ip": "10.0.0.1", "mac": "28:6A:BA:AA:BB:CC"})
        assert profile.vendor == "Apple"
        assert profile.device_type == "Mobile Phone"
        assert profile.confidence > 0

    def test_hostname_only(self):
        profile = self.pipeline.run({"ip": "10.0.0.2", "hostname": "iPhone-Pro"})
        assert profile.hostname == "iPhone-Pro"
        assert profile.device_type == "Mobile Phone"

    def test_dhcp_windows(self):
        profile = self.pipeline.run({
            "ip": "10.0.0.3",
            "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,121,249,252",
        })
        assert profile.device_type == "Windows Device"

    def test_dhcp_linux(self):
        profile = self.pipeline.run({
            "ip": "10.0.0.4",
            "dhcp_fingerprint": "1,3,6,15,26,28,51,58,59",
        })
        assert profile.device_type == "Linux/Unix Device"

    def test_mdns_chromecast(self):
        profile = self.pipeline.run({
            "ip": "10.0.0.5",
            "mdns_services": ["_googlecast._tcp.local"],
        })
        assert profile.device_type == "Chromecast / Smart TV"

    def test_ssdp_roku(self):
        profile = self.pipeline.run({
            "ip": "10.0.0.6",
            "ssdp_services": [],
            "ssdp_friendly_name": "Roku Express",
        })
        assert profile.device_type == "Roku / Smart TV"

    def test_mdns_overrides_dhcp(self):
        profile = self.pipeline.run({
            "ip": "10.0.0.7",
            "dhcp_fingerprint": "1,3,6,15,26,28,51,58,59",
            "mdns_services": ["_googlecast._tcp.local"],
        })
        assert profile.device_type == "Chromecast / Smart TV"

    def test_vmware_oui(self):
        profile = self.pipeline.run({"ip": "10.0.0.8", "mac": "00:50:56:AA:BB:CC"})
        assert profile.vendor == "VMware"
        assert profile.device_type == "Virtual Machine"

    def test_synology_oui_linux_dhcp(self):
        profile = self.pipeline.run({
            "ip": "10.0.0.9",
            "mac": "00:11:32:AA:BB:CC",
            "dhcp_fingerprint": "1,3,6,15,26,28,51,58,59",
        })
        assert profile.vendor == "Synology"
        assert profile.device_type == "NAS / Storage"

    def test_raspberry_pi_oui(self):
        profile = self.pipeline.run({"ip": "10.0.0.10", "mac": "DC:A6:32:AA:BB:CC"})
        assert profile.vendor == "Raspberry Pi"
        assert profile.device_type == "Linux/IoT Device"

    def test_empty_context(self):
        profile = self.pipeline.run({"ip": "10.0.0.11"})
        assert profile.device_type == "Unknown"
        assert profile.vendor == "Unknown"

    def test_evidence_sources_populated(self):
        profile = self.pipeline.run({
            "ip": "10.0.0.12",
            "mac": "28:6A:BA:AA:BB:CC",
            "hostname": "MacBook-Pro",
        })
        sources = {ev.source for ev in profile.evidence_sources}
        assert "oui" in sources
        assert "hostname" in sources

    def test_confidence_increases_with_more_sources(self):
        profile_single = self.pipeline.run({"ip": "10.0.0.13", "mac": "28:6A:BA:AA:BB:CC"})
        profile_multi = self.pipeline.run({
            "ip": "10.0.0.14",
            "mac": "28:6A:BA:AA:BB:CC",
            "hostname": "MacBook-Pro",
            "dhcp_fingerprint": "1,121,3,6,15,119,252,95,44,46",
        })
        assert profile_multi.confidence > profile_single.confidence

    def test_ip_always_set(self):
        profile = self.pipeline.run({"ip": "192.168.1.100"})
        assert profile.ip == "192.168.1.100"

    def test_mac_propagated(self):
        profile = self.pipeline.run({"ip": "10.0.0.15", "mac": "AA:BB:CC:DD:EE:FF"})
        assert profile.mac == "AA:BB:CC:DD:EE:FF"
