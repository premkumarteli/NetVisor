"""Shared packet capture and flow aggregation helpers."""

from .buffer import DiskBackedBuffer
from .capture import CaptureBackend, LinuxRawSocketCaptureBackend, ScapyCaptureBackend, build_capture_backend
from .analysis import PacketAnalysis, analyze_packet
from .fingerprint import compute_machine_fingerprint
from .flow_manager import FlowKey, FlowManager, FlowState, FlowSummary
from .health import CollectorHealthReport, UploadHealthSnapshot
from .network_scope import (
    PacketScopeDecision,
    PacketScopePolicy,
    build_scope_policy,
    classify_ip_scope,
    normalize_ip,
    summarize_scope_policy,
)
from .observations import DpiObservation, FlowObservation, PacketObservation
from .preflight import PreflightResult, print_preflight_report, run_preflight
from .traffic_metadata import DomainHintCache, extract_domain_hint, extract_flow_hints

__all__ = [
    "DiskBackedBuffer",
    "CaptureBackend",
    "CollectorHealthReport",
    "compute_machine_fingerprint",
    "DomainHintCache",
    "DpiObservation",
    "FlowKey",
    "FlowManager",
    "FlowObservation",
    "FlowState",
    "FlowSummary",
    "LinuxRawSocketCaptureBackend",
    "PacketAnalysis",
    "PacketScopeDecision",
    "PacketScopePolicy",
    "PacketObservation",
    "PreflightResult",
    "ScapyCaptureBackend",
    "UploadHealthSnapshot",
    "build_capture_backend",
    "build_scope_policy",
    "analyze_packet",
    "classify_ip_scope",
    "extract_domain_hint",
    "extract_flow_hints",
    "normalize_ip",
    "print_preflight_report",
    "run_preflight",
    "summarize_scope_policy",
]
