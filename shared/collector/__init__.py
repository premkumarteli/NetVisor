"""Shared packet capture and flow aggregation helpers."""

from .capture import CaptureBackend, LinuxRawSocketCaptureBackend, ScapyCaptureBackend, build_capture_backend
from .analysis import PacketAnalysis, analyze_packet
from .flow_manager import FlowKey, FlowManager, FlowState, FlowSummary
from .observations import DpiObservation, FlowObservation, PacketObservation
from .preflight import PreflightResult, preflight_exit_code, print_preflight_report, run_preflight, serialize_preflight_results
from .traffic_metadata import DomainHintCache, extract_domain_hint, extract_flow_hints

__all__ = [
    "CaptureBackend",
    "DomainHintCache",
    "DpiObservation",
    "FlowKey",
    "FlowManager",
    "FlowObservation",
    "FlowState",
    "FlowSummary",
    "LinuxRawSocketCaptureBackend",
    "PacketAnalysis",
    "PacketObservation",
    "PreflightResult",
    "ScapyCaptureBackend",
    "preflight_exit_code",
    "build_capture_backend",
    "analyze_packet",
    "extract_domain_hint",
    "extract_flow_hints",
    "print_preflight_report",
    "run_preflight",
    "serialize_preflight_results",
]
