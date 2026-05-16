"""Tests for shared.collector.health module."""

import pytest

from shared.collector.health import CollectorHealthReport, UploadHealthSnapshot


class TestUploadHealthSnapshot:
    def test_default_values(self):
        snap = UploadHealthSnapshot()
        assert snap.upload_failures == 0
        assert snap.upload_successes == 0
        assert snap.last_upload_time is None

    def test_to_dict(self):
        snap = UploadHealthSnapshot(upload_failures=3, upload_successes=10, queue_depth=5)
        d = snap.to_dict()
        assert d["upload_failures"] == 3
        assert d["upload_successes"] == 10
        assert d["queue_depth"] == 5


class TestCollectorHealthReport:
    def test_healthy_status(self):
        report = CollectorHealthReport.build(
            capture_snapshot={"health_status": "healthy", "packets_seen": 100},
            upload_snapshot={"consecutive_failures": 0},
            flow_snapshot={"active_flow_count": 10},
        )
        assert report.overall_status == "healthy"

    def test_degraded_capture(self):
        report = CollectorHealthReport.build(
            capture_snapshot={"health_status": "degraded"},
            upload_snapshot={"consecutive_failures": 0},
        )
        assert report.overall_status == "degraded"

    def test_unhealthy_both_degraded(self):
        report = CollectorHealthReport.build(
            capture_snapshot={"health_status": "degraded"},
            upload_snapshot={"consecutive_failures": 5},
        )
        assert report.overall_status == "unhealthy"

    def test_stopped_capture(self):
        report = CollectorHealthReport.build(
            capture_snapshot={"health_status": "stopped"},
            upload_snapshot={"consecutive_failures": 0},
        )
        assert report.overall_status == "stopped"

    def test_warming_status(self):
        report = CollectorHealthReport.build(
            capture_snapshot={"health_status": "warming"},
            upload_snapshot={"consecutive_failures": 0},
        )
        assert report.overall_status == "warming"

    def test_upload_only_degraded(self):
        report = CollectorHealthReport.build(
            capture_snapshot={"health_status": "healthy"},
            upload_snapshot={"consecutive_failures": 5},
        )
        assert report.overall_status == "degraded"

    def test_to_dict_structure(self):
        report = CollectorHealthReport.build(
            capture_snapshot={"health_status": "healthy"},
            upload_snapshot={"consecutive_failures": 0},
            flow_snapshot={"active_flow_count": 5},
        )
        d = report.to_dict()
        assert "overall_status" in d
        assert "capture_health" in d
        assert "upload_health" in d
        assert "flow_health" in d

    def test_empty_build(self):
        report = CollectorHealthReport.build()
        assert report.overall_status == "unknown"

    def test_to_dict_calls_compute(self):
        report = CollectorHealthReport(
            capture_health={"health_status": "healthy"},
            upload_health={"consecutive_failures": 0},
        )
        d = report.to_dict()
        assert d["overall_status"] == "healthy"
