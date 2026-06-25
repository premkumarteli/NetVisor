"""
test_vpn_detector.py — Extended test suite for the hardened VPNDetector.

Covers:
  1. Asynchronous IP classification (pending → resolved flow)
  2. Tor exit-node parsing and classification
  3. Hostname classification (VPN subdomains, authorized bypass, false-positive guard)
  4. Correct risk-score calculations for each scoring tier
  5. ASN/ISP keyword matching (VPN providers and hosting providers)
  6. Cache TTL expiry behaviour
  7. Edge cases: invalid IPs, blank hostnames, IPv6
  8. Backward compatibility wrapper (analyze_vpn)
"""

from __future__ import annotations

import ipaddress
import threading
import time
from unittest.mock import MagicMock, patch, PropertyMock
import pytest

from app.services.vpn_detector import (
    ASNLookupService,
    ASNRecord,
    TorIntelligence,
    VPNDetector,
    _classify_hostname,
    _extract_subdomain,
    _TOR_SEED_IPS,
    _ASN_CACHE_TTL_SECONDS,
    vpn_detector,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def detector():
    """VPNDetector wired with a mock ASN service and Tor intelligence."""
    tor = TorIntelligence(start_thread=False)
    d = VPNDetector(
        authorized_domains={"corp.example.com", "vpn.internal.acme.io"},
        tor_service=tor,
    )
    yield d
    d.shutdown()


@pytest.fixture()
def asn_service():
    svc = ASNLookupService()
    yield svc
    svc.shutdown()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Asynchronous IP classification
# ─────────────────────────────────────────────────────────────────────────────

class TestAsyncClassification:

    def test_pending_result_is_neutral(self, detector):
        """First call for an unknown IP triggers a background lookup; score must be 0."""
        ip = "203.0.113.50"   # TEST-NET — never a real Tor exit

        # Patch TorIntelligence so it never flags this IP
        detector._tor._exit_nodes = frozenset()

        result = detector.classify(ip)

        # The result is either pending (remote fetch) or neutral (no ASN record)
        # Both cases must NOT declare is_vpn=True with score=0
        assert result.score == 0 or result.pending
        assert result.is_vpn is False

    def test_resolved_result_is_accurate(self):
        """Once the cache is warm the detector returns the real score."""
        ip = "1.2.3.4"
        record = ASNRecord(ip=ip, asn="AS9009", isp="M247 Ltd", org="M247 Europe SRL")

        with patch.object(ASNLookupService, "lookup", return_value=(record, False)), \
             patch.object(TorIntelligence, "is_tor_exit", return_value=False):
            d = VPNDetector()
            result = d.classify(ip)
            d.shutdown()

        assert result.pending is False
        assert result.score >= 20          # hosting provider match
        assert any("M247" in r or "m247" in r for r in result.reasons)

    def test_cache_warms_across_calls(self, asn_service):
        """Second lookup for the same IP should be served from cache (no pending)."""
        ip = "198.51.100.1"
        record = ASNRecord(ip=ip, asn="AS1234", isp="TestISP", org="TestOrg")

        with asn_service._cache_lock:
            asn_service._cache[ip] = record

        result, pending = asn_service.lookup(ip)
        assert pending is False
        assert result is not None
        assert result.isp == "TestISP"

    def test_expired_cache_triggers_new_lookup(self, asn_service):
        """A record past its TTL must not be returned from cache."""
        ip = "192.0.2.77"
        stale_record = ASNRecord(ip=ip, isp="OldISP")
        # Back-date the record beyond TTL
        stale_record.fetched_at = time.monotonic() - (_ASN_CACHE_TTL_SECONDS + 1)

        with asn_service._cache_lock:
            asn_service._cache[ip] = stale_record

        _, pending = asn_service.lookup(ip)
        assert pending is True   # should have kicked off a new background fetch


# ─────────────────────────────────────────────────────────────────────────────
# 2. Tor exit node parsing and classification
# ─────────────────────────────────────────────────────────────────────────────

class TestTorIntelligence:

    _SAMPLE_FEED = (
        "ExitAddress 185.220.101.1 2024-01-01 00:00:00\n"
        "ExitAddress 185.220.101.2 2024-01-01 01:00:00\n"
        "ExitAddress 2a0b:f4c2::1 2024-01-01 02:00:00\n"
        "# comment line\n"
        "SomeOtherDirective foo bar\n"
    )

    def test_parse_exit_addresses_ipv4(self):
        ips = TorIntelligence._parse_exit_addresses(self._SAMPLE_FEED)
        assert "185.220.101.1" in ips
        assert "185.220.101.2" in ips

    def test_parse_exit_addresses_ipv6(self):
        ips = TorIntelligence._parse_exit_addresses(self._SAMPLE_FEED)
        assert "2a0b:f4c2::1" in ips

    def test_parse_ignores_non_exit_lines(self):
        ips = TorIntelligence._parse_exit_addresses(self._SAMPLE_FEED)
        for item in ips:
            # Every item must be a valid IP
            ipaddress.ip_address(item)

    def test_parse_empty_feed_returns_empty_list(self):
        ips = TorIntelligence._parse_exit_addresses("")
        assert ips == []

    def test_is_tor_exit_after_refresh(self):
        tor = TorIntelligence()
        tor.stop()   # prevent background refreshes during test

        with tor._lock:
            tor._exit_nodes = frozenset(["185.220.101.1", "51.15.43.205"])

        assert tor.is_tor_exit("185.220.101.1") is True
        assert tor.is_tor_exit("51.15.43.205") is True
        assert tor.is_tor_exit("8.8.8.8") is False

    def test_seed_list_used_when_fetch_fails(self):
        """On startup with offline feed the seed list must still cover known IPs."""
        tor = TorIntelligence.__new__(TorIntelligence)
        tor._exit_nodes = _TOR_SEED_IPS
        tor._lock = threading.RLock()
        tor._stop_event = threading.Event()

        for ip in list(_TOR_SEED_IPS)[:3]:
            assert tor.is_tor_exit(ip) is True

    def test_offline_fallback_retains_previous_set(self):
        """A failed HTTP fetch must not erase an already-loaded node set."""
        tor = TorIntelligence()
        tor.stop()

        original_nodes = frozenset(["1.2.3.4", "5.6.7.8"])
        with tor._lock:
            tor._exit_nodes = original_nodes

        with patch("requests.get", side_effect=ConnectionError("offline")):
            tor._fetch_and_update()

        with tor._lock:
            assert tor._exit_nodes == original_nodes

    def test_tor_classification_adds_40_points(self, detector):
        print("\nMOCK DEBUG - Class of detector._tor:", detector._tor.__class__)
        print("MOCK DEBUG - TorIntelligence class:", TorIntelligence)
        print("MOCK DEBUG - Are they equal:", detector._tor.__class__ is TorIntelligence)
        with patch.object(TorIntelligence, "is_tor_exit", return_value=True), \
             patch.object(ASNLookupService, "lookup", return_value=(None, False)):
            print("MOCK DEBUG - inside patch, call is_tor_exit direct on instance:", detector._tor.is_tor_exit("185.220.101.1"))
            result = detector.classify("185.220.101.1")
            print("MOCK DEBUG - inside patch, result score:", result.score)

        assert result.score >= 40
        assert result.is_vpn is True
        assert any("Tor" in r for r in result.reasons)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Hostname classification
# ─────────────────────────────────────────────────────────────────────────────

class TestHostnameClassification:

    @pytest.mark.parametrize("hostname,expected", [
        ("vpn.attacker.com", True),
        ("proxy.badactor.net", True),
        ("wireguard.exit.io", True),
        ("openvpn.malicious.org", True),
        ("tunnel.datacenter.cc", True),
        ("socks.anon.pw", True),
        ("relay.darknet.su", True),
        ("exit.nodehosting.ru", True),
        ("www.google.com", False),
        ("api.github.com", False),
        ("mail.corp.example.com", False),
    ])
    def test_vpn_subdomain_detection(self, hostname, expected):
        is_vpn, _ = _classify_hostname(hostname, frozenset())
        assert is_vpn is expected, f"Unexpected result for {hostname!r}"

    def test_authorized_domain_not_flagged(self):
        """vpn.corp.example.com must not be flagged when corp.example.com is authorized."""
        is_vpn, reason = _classify_hostname(
            "vpn.corp.example.com",
            frozenset({"corp.example.com"}),
        )
        assert is_vpn is False, f"Authorized domain incorrectly flagged: {reason}"

    def test_vpn_provider_name_in_hostname(self):
        is_vpn, reason = _classify_hostname("nordvpn-exit.com", frozenset())
        assert is_vpn is True
        assert "nord" in reason.lower()   # matches "nordvpn" or "nord vpn"

    def test_blank_hostname_returns_false(self):
        is_vpn, _ = _classify_hostname("", frozenset())
        assert is_vpn is False

    def test_hostname_with_scheme_stripped(self):
        """Accidentally passing a URL should still work."""
        is_vpn, _ = _classify_hostname("https://vpn.badactor.com/path", frozenset())
        assert is_vpn is True

    def test_extract_subdomain_tldextract(self):
        sub = _extract_subdomain("vpn.us-east.example.com")
        assert sub == "vpn"

    def test_extract_subdomain_fallback(self):
        with patch.dict("sys.modules", {"tldextract": None}):
            sub = _extract_subdomain("proxy.service.example.co.uk")
            assert sub == "proxy"

    def test_hostname_adds_25_points(self, detector):
        with patch.object(TorIntelligence, "is_tor_exit", return_value=False), \
             patch.object(ASNLookupService, "lookup",
                          return_value=(ASNRecord(ip="1.1.1.1", isp="Clean ISP"), False)):
            result = detector.classify("1.1.1.1", hostname="vpn.attacker.com")

        assert result.score >= 25
        assert any("hostname" in r.lower() or "Hostname" in r for r in result.reasons)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Risk scoring calculations
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskScoring:

    def _make_record(self, ip: str, isp: str = "", org: str = "") -> ASNRecord:
        return ASNRecord(ip=ip, asn="", isp=isp, org=org)

    def test_vpn_provider_scores_35(self, detector):
        record = self._make_record("10.0.0.1", isp="NordVPN AS")
        with patch.object(TorIntelligence, "is_tor_exit", return_value=False), \
             patch.object(ASNLookupService, "lookup", return_value=(record, False)):
            result = detector.classify("10.0.0.1")
        assert result.score == 35
        assert result.is_vpn is True

    def test_hosting_provider_scores_20(self, detector):
        record = self._make_record("10.0.0.2", isp="Leaseweb Deutschland GmbH")
        with patch.object(TorIntelligence, "is_tor_exit", return_value=False), \
             patch.object(ASNLookupService, "lookup", return_value=(record, False)):
            result = detector.classify("10.0.0.2")
        assert result.score == 20
        assert result.is_vpn is False   # hosting alone is below threshold

    def test_combined_tor_and_hosting_scores_60(self, detector):
        record = self._make_record("10.0.0.3", isp="Hetzner Online GmbH")
        with patch.object(TorIntelligence, "is_tor_exit", return_value=True), \
             patch.object(ASNLookupService, "lookup", return_value=(record, False)):
            result = detector.classify("10.0.0.3")
        # Tor=40 + hosting=20 = 60
        assert result.score == 60
        assert result.is_vpn is True

    def test_all_signals_combined(self, detector):
        """Tor + VPN provider + VPN hostname → 40+35+25 = 100."""
        record = self._make_record("10.0.0.4", isp="ProtonVPN AG")
        with patch.object(TorIntelligence, "is_tor_exit", return_value=True), \
             patch.object(ASNLookupService, "lookup", return_value=(record, False)):
            result = detector.classify("10.0.0.4", hostname="vpn.proton.me")
        assert result.score == 100
        assert result.is_vpn is True
        assert len(result.reasons) == 3

    def test_clean_ip_scores_zero(self, detector):
        record = self._make_record("8.8.8.8", isp="Google LLC")
        with patch.object(TorIntelligence, "is_tor_exit", return_value=False), \
             patch.object(ASNLookupService, "lookup", return_value=(record, False)):
            result = detector.classify("8.8.8.8", hostname="dns.google")
        assert result.score == 0
        assert result.is_vpn is False

    def test_threshold_boundary_34_not_vpn(self, detector):
        """Score of 34 must NOT cross the is_vpn threshold of 35."""
        record = self._make_record("10.0.0.5", isp="OVH SAS")
        with patch.object(TorIntelligence, "is_tor_exit", return_value=False), \
             patch.object(ASNLookupService, "lookup", return_value=(record, False)):
            result = detector.classify("10.0.0.5")   # no hostname
        assert result.score == 20
        assert result.is_vpn is False

    def test_no_double_counting_vpn_and_hosting(self, detector):
        """ISP matching a VPN provider name must not also add hosting points."""
        record = self._make_record("10.0.0.6", isp="NordVPN Hetzner GmbH")
        with patch.object(TorIntelligence, "is_tor_exit", return_value=False), \
             patch.object(ASNLookupService, "lookup", return_value=(record, False)):
            result = detector.classify("10.0.0.6")
        # VPN provider matched first (+35); hosting branch must be skipped
        assert result.score == 35


# ─────────────────────────────────────────────────────────────────────────────
# 5. ASN / ISP keyword matching
# ─────────────────────────────────────────────────────────────────────────────

class TestASNKeywordMatching:

    @pytest.mark.parametrize("isp", [
        "NordVPN Technology",
        "Proton AG",
        "Surfshark B.V.",
        "ExpressVPN Media Inc.",
        "Private Internet Access",
        "Mullvad VPN",
        "Windscribe Limited",
        "CyberGhost S.R.L.",
    ])
    def test_known_vpn_providers(self, detector, isp):
        record = ASNRecord(ip="1.1.1.1", isp=isp, org="")
        with patch.object(TorIntelligence, "is_tor_exit", return_value=False), \
             patch.object(ASNLookupService, "lookup", return_value=(record, False)):
            result = detector.classify("1.1.1.1")
        assert result.score >= 35, f"Expected VPN match for ISP: {isp!r}"
        assert result.is_vpn is True

    @pytest.mark.parametrize("isp", [
        "M247 Europe SRL",
        "Datacamp Limited",
        "Leaseweb Netherlands B.V.",
        "OVH SAS",
        "Vultr Holdings LLC",
        "DigitalOcean LLC",
        "Hetzner Online GmbH",
        "Frantech Solutions",
    ])
    def test_hosting_providers_below_threshold(self, detector, isp):
        record = ASNRecord(ip="2.2.2.2", isp=isp, org="")
        with patch.object(TorIntelligence, "is_tor_exit", return_value=False), \
             patch.object(ASNLookupService, "lookup", return_value=(record, False)):
            result = detector.classify("2.2.2.2")
        assert result.score == 20, f"Expected hosting score 20 for ISP: {isp!r}"
        assert result.is_vpn is False


# ─────────────────────────────────────────────────────────────────────────────
# 6. Edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:

    def test_invalid_ip_does_not_crash(self, detector):
        result = detector.classify("not-an-ip")
        assert result is not None

    def test_ipv6_tor_exit_detected(self, detector):
        ipv6 = "2a0b:f4c2::1"
        with patch.object(TorIntelligence, "is_tor_exit",
                          side_effect=lambda ip: ip == ipv6), \
             patch.object(ASNLookupService, "lookup", return_value=(None, False)):
            result = detector.classify(ipv6)
        assert result.score >= 40
        assert result.is_vpn is True

    def test_none_hostname_skips_check(self, detector):
        record = ASNRecord(ip="3.3.3.3", isp="Clean Telecom")
        with patch.object(TorIntelligence, "is_tor_exit", return_value=False), \
             patch.object(ASNLookupService, "lookup", return_value=(record, False)):
            result = detector.classify("3.3.3.3", hostname=None)
        assert result.score == 0

    def test_pending_result_fields(self, detector):
        """A pending result must carry ip and pending=True, score=0."""
        with patch.object(TorIntelligence, "is_tor_exit", return_value=False), \
             patch.object(ASNLookupService, "lookup", return_value=(None, True)):
            result = detector.classify("4.4.4.4")
        assert result.pending is True
        assert result.ip == "4.4.4.4"
        assert result.score == 0
        assert result.is_vpn is False

    def test_asn_record_expiry(self):
        r = ASNRecord(ip="1.1.1.1", isp="X")
        r.fetched_at = time.monotonic() - (_ASN_CACHE_TTL_SECONDS + 1)
        assert r.is_expired() is True

    def test_asn_record_not_expired(self):
        r = ASNRecord(ip="1.1.1.1", isp="X")
        assert r.is_expired() is False


# ─────────────────────────────────────────────────────────────────────────────
# 7. Backward Compatibility Wrapper Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_vpn_detector_scores_keyword_host():
    score, reason, provider = vpn_detector.analyze_vpn("10.0.0.10", "8.8.8.8", 443, host="vpn.example.com")
    assert score > 0
    assert "keyword" in reason.lower()
    assert provider is None


def test_vpn_detector_scores_suspicious_port():
    score, reason, provider = vpn_detector.analyze_vpn("10.0.0.10", "8.8.8.8", 1194)
    assert score > 0
    assert "port" in reason.lower()
    assert provider is None


# ─────────────────────────────────────────────────────────────────────────────
# 8. Modular Detector Unit Tests (Phase 11B)
# ─────────────────────────────────────────────────────────────────────────────

def test_wireguard_heuristic_detector():
    from app.engines.vpn.wireguard import WireGuardHeuristicDetector
    detector = WireGuardHeuristicDetector()
    
    # 1. Non-UDP flow should be ignored
    flow_tcp = {"protocol": "TCP", "src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 51820, "dst_port": 51820, "analysis_signals": ["wg_size_148"]}
    assert detector.analyze(flow_tcp) is False

    # 2. First flow (unidirectional) with wg_size_148
    flow_init = {"protocol": "UDP", "src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 51820, "dst_port": 51820, "analysis_signals": ["wg_size_148"]}
    assert detector.analyze(flow_init) is False

    # 3. Reverse direction flow with wg_size_92 -> should trigger bidirectional match
    flow_resp = {"protocol": "UDP", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.50", "src_port": 51820, "dst_port": 51820, "analysis_signals": ["wg_size_92"]}
    assert detector.analyze(flow_resp) is True


def test_openvpn_signature_detector():
    from app.engines.vpn.openvpn import OpenVPNSignatureDetector
    detector = OpenVPNSignatureDetector()

    # 1. No OpenVPN signal
    flow_clean = {"analysis_signals": []}
    is_ovpn, reason = detector.analyze(flow_clean)
    assert is_ovpn is False

    # 2. UDP OpenVPN signal
    flow_udp = {"analysis_signals": ["openvpn_udp_opcode_7"]}
    is_ovpn, reason = detector.analyze(flow_udp)
    assert is_ovpn is True
    assert "UDP opcode 7" in reason

    # 3. TCP OpenVPN signal
    flow_tcp = {"analysis_signals": ["openvpn_tcp_opcode_4"]}
    is_ovpn, reason = detector.analyze(flow_tcp)
    assert is_ovpn is True
    assert "TCP opcode 4" in reason


def test_tls_certificate_detector():
    from app.engines.vpn.tls_cert import TLSCertificateDetector
    detector = TLSCertificateDetector()

    # 1. Matching SNI
    flow_sni = {"sni": "us-ny.mullvad.net"}
    is_vpn, reason = detector.analyze(flow_sni)
    assert is_vpn is True
    assert "mullvad" in reason

    # 2. Matching Issuer CN
    flow_issuer = {"issuer_cn": "NordVPN Certification Authority"}
    is_vpn, reason = detector.analyze(flow_issuer)
    assert is_vpn is True
    assert "nordvpn" in reason

    # 3. Matching Subject CN
    flow_subject = {"subject_cn": "ExpressVPN Egress Endpoint"}
    is_vpn, reason = detector.analyze(flow_subject)
    assert is_vpn is True
    assert "expressvpn" in reason


def test_asn_reputation_detector():
    from app.engines.vpn.asn_detector import ASNReputationDetector
    from unittest.mock import patch
    detector = ASNReputationDetector()

    # 1. Test Tor exit node matching
    with patch("app.services.vpn_detector.TorIntelligence.is_tor_exit", return_value=True):
        is_tor, is_asn, provider, reason = detector.analyze("185.220.101.1")
        assert is_tor is True
        assert provider == "Tor Exit Node"

    # 2. Test Datacenter provider matching
    with patch("app.utils.asn_lookup.asn_lookup_service.lookup_asn_details") as mock_lookup:
        mock_lookup.return_value = {"asn": 16276, "organization": "OVH SAS"}
        is_tor, is_asn, provider, reason = detector.analyze("1.2.3.4")
        assert is_asn is True
        assert provider == "Ovh"
        assert "ovh" in reason

    # 3. Test VPN provider matching
    with patch("app.utils.asn_lookup.asn_lookup_service.lookup_asn_details") as mock_lookup:
        mock_lookup.return_value = {"asn": 136787, "organization": "Mullvad VPN"}
        is_tor, is_asn, provider, reason = detector.analyze("5.6.7.8")
        assert is_asn is True
        assert provider == "Mullvad"


def test_asn_lookup_pruning_and_pending_count():
    from concurrent.futures import Future
    from app.services.vpn_detector import ASNLookupService
    from unittest.mock import patch

    svc = ASNLookupService()
    try:
        f_done1 = Future()
        f_done1.set_result(None)
        
        f_done2 = Future()
        f_done2.set_result(None)
        
        f_pending = Future()
        
        with svc._pending_lock:
            svc._pending["1.1.1.1"] = f_done1
            svc._pending["2.2.2.2"] = f_done2
            svc._pending["3.3.3.3"] = f_pending
            
        assert svc.pending_count == 1
        
        with patch.object(svc._executor, "submit") as mock_submit:
            mock_submit.return_value = Future()
            svc.lookup("8.8.8.8")
            
        with svc._pending_lock:
            assert "1.1.1.1" not in svc._pending
            assert "2.2.2.2" not in svc._pending
            assert "3.3.3.3" in svc._pending
            assert "8.8.8.8" in svc._pending
    finally:
        svc.shutdown()


