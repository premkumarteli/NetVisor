"""Adversarial test suite for Phase 4: Threat Engine & VPN Hardening.

Verifies:
1. Welford's online single-pass variance and standard deviation numerical accuracy.
2. C2 Beaconing detector integration with Welford variance.
3. Public Suffix List (PSL) Trie parsing and multi-part ccTLD / eTLD+1 isolation.
4. Elimination of false positives in DNS tunneling detector across shared ccTLDs.
5. Token-bounded regex in TLS/VPN certificate detector preventing false positive matches on words like 'utopia', 'olympian', 'ethiopia'.
6. Zero-copy AF_PACKET capture backend registration and factory instantiation.
"""

from datetime import datetime, timezone, timedelta
import math
import statistics
import pytest

from backend.engines.threat.beaconing import BeaconingDetector, welford_online_variance
from backend.engines.threat.dns_tunneling import DNSTunnelingDetector, PSLTrie
from backend.engines.threat.state import SlidingWindowStore
from backend.engines.vpn.tls_cert import TLSCertificateDetector
from packet_engine.backend import build_capture_backend
from packet_engine.af_packet_backend import AFPacketCaptureBackend


def test_welford_online_variance_numerical_accuracy():
    """Verify Welford's online algorithm matches Python's statistics module exactly."""
    intervals = [10.2, 9.8, 10.1, 10.0, 9.9, 10.3, 9.7, 10.0]
    
    mean_val, stdev, cov = welford_online_variance(intervals)

    expected_mean = statistics.mean(intervals)
    expected_stdev = statistics.pstdev(intervals)
    expected_cov = expected_stdev / expected_mean

    assert mean_val == pytest.approx(expected_mean, rel=1e-6)
    assert stdev == pytest.approx(expected_stdev, rel=1e-6)
    assert cov == pytest.approx(expected_cov, rel=1e-6)

    # Empty and single-element edge cases
    assert welford_online_variance([]) == (0.0, 0.0, 0.0)
    assert welford_online_variance([5.0]) == (5.0, 0.0, 0.0)


def test_beaconing_detector_with_welford():
    """Verify BeaconingDetector catches low-variance periodic C2 pulses using Welford."""
    store = SlidingWindowStore()
    detector = BeaconingDetector(store=store)

    now = datetime(2026, 11, 28, 12, 0, 0, tzinfo=timezone.utc)
    target_ip = "192.168.1.100"
    c2_ip = "45.33.32.156"

    # Inject periodic beacon every 10 seconds (+/- 0.1s jitter)
    finding = None
    for i in range(15):
        t = now + timedelta(seconds=i * 10.0 + (0.05 if i % 2 == 0 else -0.05))
        flow = {"src_ip": target_ip, "dst_ip": c2_ip, "dst_port": 443}
        f = detector.analyze(flow, t)
        if f:
            finding = f

    assert finding is not None
    assert finding.finding_type == "beaconing"
    assert finding.target_ip == target_ip
    assert finding.details["average_interval_seconds"] == pytest.approx(10.0, abs=0.2)
    assert finding.details["interval_stdev"] < 0.2


def test_psl_trie_multi_part_tld_resolution():
    """Verify that PSLTrie correctly extracts eTLD+1 for multi-part domains."""
    trie = PSLTrie()

    # 1. Standard single-part TLD
    sub, parent = trie.extract_etld_plus_one("data.exfiltration.attacker.com")
    assert parent == "attacker.com"
    assert sub == "data.exfiltration"

    # 2. Multi-part UK TLD (.co.uk)
    sub, parent = trie.extract_etld_plus_one("tunnel.c2.target.co.uk")
    assert parent == "target.co.uk"
    assert sub == "tunnel.c2"

    # 3. Australian academic TLD (.edu.au)
    sub, parent = trie.extract_etld_plus_one("research.lab.uni.edu.au")
    assert parent == "uni.edu.au"
    assert sub == "research.lab"

    # 4. Cloudflare / Github Pages eTLD
    sub, parent = trie.extract_etld_plus_one("mysite.github.io")
    assert parent == "mysite.github.io"
    assert sub == ""

    # 5. Bare domain without subdomain
    sub, parent = trie.extract_etld_plus_one("google.com")
    assert parent == "google.com"
    assert sub == ""


def test_dns_tunneling_no_false_positives_on_cctld():
    """Verify that benign queries across different .co.uk domains are not grouped together."""
    detector = DNSTunnelingDetector()
    now = datetime(2026, 11, 28, 12, 0, 0, tzinfo=timezone.utc)
    client_ip = "10.0.1.50"

    # User visits 30 distinct legitimate .co.uk websites
    # Under old logic, all 30 were treated as subdomains of 'co.uk' and triggered an alert!
    legit_sites = [f"site{i}.co.uk" for i in range(30)]

    findings = []
    for site in legit_sites:
        flow = {"src_ip": client_ip, "domain": site}
        f = detector.analyze(flow, now)
        if f:
            findings.append(f)

    # Must produce ZERO false positive alerts because each site has its own parent domain
    assert len(findings) == 0, f"False positive triggered for benign .co.uk domains: {findings}"


def test_vpn_tls_cert_token_bounded_regex():
    """Verify token-bounded regex eliminates false positives while strictly catching VPNs."""
    detector = TLSCertificateDetector()

    # Adversarial false positive candidates (contain 'pia' as substring)
    false_positive_cases = [
        {"sni": "utopia.org"},
        {"sni": "olympian.athletics.com"},
        {"sni": "theolympian.com"},
        {"domain": "cornucopia.net"},
        {"domain": "ethiopia.gov.et"},
        {"issuer_cn": "Sepia Photo Filters LLC"},
        {"subject_cn": "Grand Piano Concerts Inc"},
        {"sni": "casio-piano.music.store"},
    ]

    for flow in false_positive_cases:
        is_vpn, reason = detector.analyze(flow)
        assert is_vpn is False, f"False positive triggered for benign flow {flow}: {reason}"

    # True positive PIA cases
    true_positive_pia = [
        {"sni": "us-east.pia.com"},
        {"sni": "vpn-pia.net"},
        {"domain": "privateinternetaccess.com"},
        {"issuer_cn": "Private Internet Access CA"},
        {"subject_cn": "PIA Wireguard Node 01"},
    ]

    for flow in true_positive_pia:
        is_vpn, reason = detector.analyze(flow)
        assert is_vpn is True, f"Failed to detect legitimate PIA VPN in {flow}"
        assert "pia" in reason.lower()

    # True positive other VPN providers
    true_positive_others = [
        {"sni": "node-12.mullvad.net", "provider": "mullvad"},
        {"sni": "us843.nordvpn.com", "provider": "nordvpn"},
        {"issuer_cn": "ProtonVPN Certificate Authority", "provider": "proton"},
        {"domain": "nl-ams.surfshark.com", "provider": "surfshark"},
        {"subject_cn": "ExpressVPN Gateway", "provider": "expressvpn"},
    ]

    for flow in true_positive_others:
        is_vpn, reason = detector.analyze(flow)
        assert is_vpn is True, f"Failed to detect {flow['provider']} in {flow}"
        assert flow["provider"] in reason.lower()


def test_af_packet_backend_factory_wiring():
    """Verify that build_capture_backend correctly returns AFPacketCaptureBackend."""
    backend = build_capture_backend(
        role="capture",
        interface="eth0",
        requested_backend="af_packet",
    )
    assert isinstance(backend, AFPacketCaptureBackend)
    assert backend.backend_name == "af_packet"
