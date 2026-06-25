from datetime import datetime, timedelta
from app.engines.common.config import EngineConfig
from app.engines.threat.state import SlidingWindowStore
from app.engines.threat.exfiltration import ExfiltrationDetector
from app.engines.threat.port_scan import PortScanDetector
from app.engines.threat.dns_tunneling import DNSTunnelingDetector
from app.engines.threat.beaconing import BeaconingDetector
from shared.engine import Severity

def test_config_overrides_exfiltration():
    config = EngineConfig()
    # Override default large upload threshold (5MB) to 1MB
    config.large_upload_threshold = 1000000

    detector = ExfiltrationDetector(config)

    # A flow with 2MB upload should trigger a finding under overridden config
    flow = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "bytes_out": 2000000}
    finding = detector.analyze(flow, datetime.utcnow())
    assert finding is not None
    assert finding.finding_type == "large_upload"
    assert finding.details["mb_uploaded"] == 2.0

    # A flow with 800KB should not trigger
    flow_small = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "bytes_out": 800000}
    finding_small = detector.analyze(flow_small, datetime.utcnow())
    assert finding_small is None

def test_dns_tunneling_ttl_pruning():
    config = EngineConfig()
    # Set short TTL for testing
    config.dns_tunneling_ttl = 5
    config.dns_tunneling_bloom_threshold = 2

    detector = DNSTunnelingDetector(config)

    start_time = datetime(2026, 3, 18, 10, 0, 0)

    # Feed 2 unique subdomains at start time
    assert detector.analyze({"src_ip": "10.0.0.1", "domain": "sub1.example.com"}, start_time) is None
    assert detector.analyze({"src_ip": "10.0.0.1", "domain": "sub2.example.com"}, start_time) is None

    # A third subdomain at start_time + 2 seconds (within 5s TTL) should trigger a bloom finding (threshold 2)
    finding = detector.analyze({"src_ip": "10.0.0.1", "domain": "sub3.example.com"}, start_time + timedelta(seconds=2))
    assert finding is not None
    assert finding.finding_type == "dns_tunneling"
    assert finding.details["unique_subdomain_count"] == 3

    # Reset/Clear counts (for isolation in this test function)
    detector.dns_subdomain_counts.clear()

    # Feed 2 subdomains at start_time
    assert detector.analyze({"src_ip": "10.0.0.1", "domain": "sub1.example.com"}, start_time) is None
    assert detector.analyze({"src_ip": "10.0.0.1", "domain": "sub2.example.com"}, start_time) is None

    # Feed a third subdomain at start_time + 10 seconds (exceeds 5s TTL). The first 2 should be pruned, leaving count = 1. No finding.
    finding_delayed = detector.analyze({"src_ip": "10.0.0.1", "domain": "sub3.example.com"}, start_time + timedelta(seconds=10))
    assert finding_delayed is None
    assert len(detector.dns_subdomain_counts["10.0.0.1"]["example.com"]) == 1

def test_beaconing_cov_details():
    config = EngineConfig()
    config.beaconing_min_events = 3
    config.beaconing_window = 100
    config.beaconing_cov_threshold = 0.05

    store = SlidingWindowStore()
    detector = BeaconingDetector(store, config)

    # Feed 3 events spaced exactly 10s apart
    t0 = datetime(2026, 3, 18, 10, 0, 0)
    flow = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dst_port": 80}

    assert detector.analyze(flow, t0) is None
    assert detector.analyze(flow, t0 + timedelta(seconds=10)) is None

    # The 3rd event should trigger beaconing with cov = 0.0
    finding = detector.analyze(flow, t0 + timedelta(seconds=20))
    assert finding is not None
    assert finding.finding_type == "beaconing"
    assert finding.details["cov"] == 0.0
    assert finding.details["average_interval_seconds"] == 10.0
    assert finding.details["interval_stdev"] == 0.0
