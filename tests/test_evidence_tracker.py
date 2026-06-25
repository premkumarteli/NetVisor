import pytest
from app.engines.common.evidence import EvidenceTracker

def test_evidence_tracker_confidence_math():
    weights = {
        "oui": 0.15,
        "hostname": 0.10,
        "dhcp": 0.40
    }
    tracker = EvidenceTracker(weights)

    # Add evidence
    tracker.add_evidence("oui", "Apple")
    tracker.add_evidence("hostname", "DESKTOP-ABC")
    tracker.add_evidence("dhcp", "dhcp_fingerprint_here")

    # Assert calculations
    assert tracker.total_confidence == 0.65
    assert tracker.get_confidence_level() == "medium"

def test_evidence_tracker_confidence_limits():
    weights = {
        "oui": 0.15,
        "hostname": 0.10,
        "dhcp": 0.40,
        "mdns": 0.20,
        "ssdp": 0.15,
        "active_probe": 0.15
    }
    tracker = EvidenceTracker(weights)

    # Add all evidence to exceed 1.0
    for source in weights:
        tracker.add_evidence(source, "dummy_value")

    # Assert it caps at 1.0 and is high
    assert tracker.total_confidence == 1.0
    assert tracker.get_confidence_level() == "high"

def test_evidence_tracker_unknown_source():
    weights = {
        "oui": 0.15
    }
    tracker = EvidenceTracker(weights)
    tracker.add_evidence("unknown", "value")

    # Unknown source has 0.0 weight
    assert tracker.total_confidence == 0.0
    assert tracker.get_confidence_level() == "low"
