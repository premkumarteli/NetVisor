"""
Consolidated collector health reporting for agent and gateway heartbeats.

Provides a single structured health snapshot that combines capture backend
metrics, upload pipeline metrics, and flow manager metrics into one payload
that the backend can store and the Fleet UI can display.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(slots=True)
class UploadHealthSnapshot:
    """Snapshot of upload pipeline health metrics."""

    upload_failures: int = 0
    upload_successes: int = 0
    last_upload_time: Optional[str] = None
    last_upload_error: Optional[str] = None
    queue_depth: int = 0
    consecutive_failures: int = 0
    buffer_disk_usage_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "upload_failures": self.upload_failures,
            "upload_successes": self.upload_successes,
            "last_upload_time": self.last_upload_time,
            "last_upload_error": self.last_upload_error,
            "queue_depth": self.queue_depth,
            "consecutive_failures": self.consecutive_failures,
            "buffer_disk_usage_bytes": self.buffer_disk_usage_bytes,
        }


@dataclass(slots=True)
class CollectorHealthReport:
    """
    Unified health report combining capture, upload, and flow metrics.

    Used by both agent and gateway heartbeat payloads to surface full
    operational health to the backend and Fleet UI.
    """

    # Capture health — populated from CaptureBackend.status_snapshot()
    capture_health: Dict[str, Any] = field(default_factory=dict)

    # Upload health — populated from UploadManager.health_snapshot()
    upload_health: Dict[str, Any] = field(default_factory=dict)

    # Flow manager health — populated from FlowManager.status_snapshot()
    flow_health: Dict[str, Any] = field(default_factory=dict)

    # Overall health status derived from component health
    overall_status: str = "unknown"

    def compute_overall_status(self) -> str:
        """
        Derive an overall health status from component health signals.

        Returns one of: healthy, degraded, unhealthy, stopped, unknown
        """
        capture_status = str(self.capture_health.get("health_status") or "unknown")
        upload_failures = int(self.upload_health.get("consecutive_failures") or 0)
        upload_error = self.upload_health.get("last_upload_error")

        # Stopped capture is the most critical signal
        if capture_status == "stopped":
            self.overall_status = "stopped"
            return self.overall_status

        # Unhealthy: capture degraded AND upload is failing
        if capture_status == "degraded" and upload_failures >= 3:
            self.overall_status = "unhealthy"
            return self.overall_status

        # Degraded: capture degraded OR upload failing
        if capture_status == "degraded" or upload_failures >= 3:
            self.overall_status = "degraded"
            return self.overall_status

        # Warming: capture just started, no packets yet
        if capture_status == "warming":
            self.overall_status = "warming"
            return self.overall_status

        # Healthy: capture healthy and upload is working
        if capture_status == "healthy" and upload_failures < 3:
            self.overall_status = "healthy"
            return self.overall_status

        self.overall_status = "unknown"
        return self.overall_status

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for heartbeat payload."""
        self.compute_overall_status()
        return {
            "overall_status": self.overall_status,
            "capture_health": dict(self.capture_health),
            "upload_health": dict(self.upload_health),
            "flow_health": dict(self.flow_health),
        }

    @classmethod
    def build(
        cls,
        *,
        capture_snapshot: Dict[str, Any] | None = None,
        upload_snapshot: Dict[str, Any] | None = None,
        flow_snapshot: Dict[str, Any] | None = None,
    ) -> "CollectorHealthReport":
        """Factory: build a report from component snapshots."""
        report = cls(
            capture_health=dict(capture_snapshot or {}),
            upload_health=dict(upload_snapshot or {}),
            flow_health=dict(flow_snapshot or {}),
        )
        report.compute_overall_status()
        return report
