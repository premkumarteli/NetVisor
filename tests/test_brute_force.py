"""Tests for BruteForceDetector — port 22/3389/445/80/443 brute force login detection.

Thresholds (from EngineConfig):
  - attempts >= 15 within 60s window
  - duration < 1.0s  AND  byte_count < 500  AND  dst_port in {22,3389,445,80,443}
"""
from datetime import datetime, timedelta
import pytest
from backend.engines.threat.engine import ThreatEngine
from engine import EngineResult


def _ts(offset_sec: int = 0) -> str:
    base = datetime(2026, 1, 1, 0, 0, 0)
    return (base + timedelta(seconds=offset_sec)).strftime("%Y-%m-%d %H:%M:%S")


def _flow(src, dst, port, offset_sec=0, byte_count=100, duration=0.1):
    return {
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "protocol": "TCP",
        "byte_count": byte_count,
        "duration": duration,
        "last_seen": _ts(offset_sec),
    }


# ── core trigger logic ───────────────────────────────────────────────

class TestBruteForceBasicTrigger:
    def test_14_attempts_no_alert(self):
        engine = ThreatEngine()
        for i in range(14):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
            assert len(res.findings) == 0

    def test_15_attempts_triggers_alert(self):
        engine = ThreatEngine()
        for i in range(14):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
            assert len(res.findings) == 0
        res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, 14))
        assert len(res.findings) == 1
        f = res.findings[0]
        assert f.finding_type == "brute_force"
        assert f.severity.name == "CRITICAL"
        assert f.confidence == pytest.approx(0.90)
        assert f.target_ip == "10.0.0.1"
        assert f.details["failed_attempts"] >= 15

    def test_16_attempts_triggers_alert(self):
        engine = ThreatEngine()
        for i in range(16):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
        assert len(res.findings) == 1

    def test_alert_once_per_window_not_repeated(self):
        engine = ThreatEngine()
        for i in range(20):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
        assert len(res.findings) == 1


# ── target port coverage ─────────────────────────────────────────────

class TestBruteForceTargetPorts:
    @pytest.mark.parametrize("port", [22, 3389, 445, 80, 443])
    def test_all_brute_force_ports_trigger(self, port):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", port, i))
        assert len(res.findings) == 1
        assert res.findings[0].details["dst_port"] == port

    def test_non_brute_force_port_ignored(self):
        engine = ThreatEngine()
        for i in range(20):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 8080, i))
        assert len(res.findings) == 0

    def test_non_brute_force_port_5432_ignored(self):
        engine = ThreatEngine()
        for i in range(20):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 5432, i))
        assert len(res.findings) == 0


# ── flow field filter: byte_count / duration ─────────────────────────

class TestBruteForceFlowFilters:
    def test_high_byte_count_ignored(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i, byte_count=600))
        assert len(res.findings) == 0

    def test_byte_count_exactly_500_ignored(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i, byte_count=500))
        assert len(res.findings) == 0

    def test_byte_count_499_triggers(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i, byte_count=499))
        assert len(res.findings) == 1

    def test_long_duration_ignored(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i, duration=1.5))
        assert len(res.findings) == 0

    def test_duration_exactly_1_0_ignored(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i, duration=1.0))
        assert len(res.findings) == 0

    def test_duration_0_99_triggers(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i, duration=0.99))
        assert len(res.findings) == 1

    def test_zero_byte_count_triggers(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i, byte_count=0))
        assert len(res.findings) == 1

    def test_zero_duration_triggers(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i, duration=0))
        assert len(res.findings) == 1


# ── sliding window expiry ────────────────────────────────────────────

class TestBruteForceWindow:
    def test_flows_outside_window_ignored(self):
        engine = ThreatEngine()
        base = datetime(2026, 1, 1, 0, 0, 0)
        for i in range(10):
            ts = (base + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
            res = engine.analyze({
                "src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dst_port": 22,
                "protocol": "TCP", "byte_count": 50, "duration": 0.1, "last_seen": ts,
            })
            assert len(res.findings) == 0

        # 10 flows in first 10 seconds; then 70s gap pushes them out of 60s window
        ts = (base + timedelta(seconds=80)).strftime("%Y-%m-%d %H:%M:%S")
        res = engine.analyze({
            "src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dst_port": 22,
            "protocol": "TCP", "byte_count": 50, "duration": 0.1, "last_seen": ts,
        })
        # After window expiry, only 1 flow in window — no alert
        assert len(res.findings) == 0

    def test_within_window_triggers(self):
        engine = ThreatEngine()
        base = datetime(2026, 1, 1, 0, 0, 0)
        for i in range(15):
            ts = (base + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
            res = engine.analyze({
                "src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dst_port": 22,
                "protocol": "TCP", "byte_count": 50, "duration": 0.1, "last_seen": ts,
            })
        assert len(res.findings) == 1


# ── per-key isolation ────────────────────────────────────────────────

class TestBruteForceKeyIsolation:
    def test_different_src_ip_independent(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
        assert len(res.findings) == 1

        # Different src_ip should not trigger — only 1 flow for 10.0.0.2
        res = engine.analyze(_flow("10.0.0.2", "192.168.1.1", 22, 15))
        assert len(res.findings) == 0

    def test_different_dst_ip_independent(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
        assert len(res.findings) == 1

        res = engine.analyze(_flow("10.0.0.1", "192.168.1.2", 22, 15))
        assert len(res.findings) == 0

    def test_different_dst_port_independent(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
        assert len(res.findings) == 1

        # Port 3389 is a separate key — needs its own 15 attempts
        res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 3389, 15))
        assert len(res.findings) == 0

    def test_two_targets_each_independent(self):
        engine = ThreatEngine()
        # 15 flows to dst1
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
        assert len(res.findings) == 1

        # 15 flows to dst2 — different key, should also trigger
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.2", 22, 100 + i))
        assert len(res.findings) == 1


# ── missing / malformed fields ───────────────────────────────────────

class TestBruteForceEdgeCases:
    def test_missing_src_ip_ignored(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze({"dst_ip": "192.168.1.1", "dst_port": 22,
                                  "byte_count": 50, "duration": 0.1, "last_seen": _ts(i)})
        assert len(res.findings) == 0

    def test_missing_dst_ip_ignored(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze({"src_ip": "10.0.0.1", "dst_port": 22,
                                  "byte_count": 50, "duration": 0.1, "last_seen": _ts(i)})
        assert len(res.findings) == 0

    def test_missing_dst_port_ignored(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze({"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1",
                                  "byte_count": 50, "duration": 0.1, "last_seen": _ts(i)})
        assert len(res.findings) == 0

    def test_empty_src_ip_ignored(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze({"src_ip": "", "dst_ip": "192.168.1.1", "dst_port": 22,
                                  "byte_count": 50, "duration": 0.1, "last_seen": _ts(i)})
        assert len(res.findings) == 0

    def test_non_numeric_byte_count_treated_as_zero(self):
        # Detector falls through to 0.0 on bad values; 0 < 500 so it still qualifies
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze({"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1",
                                  "dst_port": 22, "byte_count": "not_a_number",
                                  "duration": 0.1, "last_seen": _ts(i)})
        assert len(res.findings) == 1

    def test_non_numeric_duration_treated_as_zero(self):
        # Detector falls through to 0.0 on bad values; 0 < 1.0 so it still qualifies
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze({"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1",
                                  "dst_port": 22, "byte_count": 50,
                                  "duration": "slow", "last_seen": _ts(i)})
        assert len(res.findings) == 1

    def test_none_byte_count_treated_as_zero(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze({"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1",
                                  "dst_port": 22, "byte_count": None,
                                  "duration": 0.1, "last_seen": _ts(i)})
        assert len(res.findings) == 1


# ── metrics ──────────────────────────────────────────────────────────

class TestBruteForceMetrics:
    def test_execution_count_increments(self):
        engine = ThreatEngine()
        for i in range(5):
            engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
        assert engine.metrics()["executions"] == 5

    def test_findings_generated_count(self):
        engine = ThreatEngine()
        for i in range(15):
            engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
        assert engine.metrics()["findings_generated"] == 1

    def test_no_finding_counted_as_zero(self):
        engine = ThreatEngine()
        for i in range(5):
            engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
        assert engine.metrics()["findings_generated"] == 0


# ── finding evidence content ─────────────────────────────────────────

class TestBruteForceEvidence:
    def test_evidence_contains_src_dst_port(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 22, i))
        f = res.findings[0]
        evidence_str = f.evidence[0]
        assert "10.0.0.1" in evidence_str
        assert "192.168.1.1" in evidence_str
        assert "22" in evidence_str
        assert "Brute Force" in evidence_str

    def test_details_dict_structure(self):
        engine = ThreatEngine()
        for i in range(15):
            res = engine.analyze(_flow("10.0.0.1", "192.168.1.1", 3389, i))
        f = res.findings[0]
        assert f.details["src_ip"] == "10.0.0.1"
        assert f.details["dst_ip"] == "192.168.1.1"
        assert f.details["dst_port"] == 3389
        assert f.details["failed_attempts"] >= 15
