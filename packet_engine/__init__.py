"""Unified Packet Engine for NetVisor: Handles low-level capture, 5-tuple parsing, DPI extraction, flow aggregation, and traffic classification."""

from .backend import CaptureBackend, LinuxRawSocketCaptureBackend, ScapyCaptureBackend, build_capture_backend
from .classifier import PacketAnalysis, analyze_packet
from .diagnostics import PreflightResult, preflight_exit_code, print_preflight_report, run_preflight, serialize_preflight_results
from .flow_aggregator import FlowKey, FlowManager, FlowState, FlowSummary
from .metadata import DomainHintCache, extract_domain_hint, extract_flow_hints, extract_ja4_fingerprint
from .parser import DpiObservation, FlowObservation, PacketObservation

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
    "analyze_packet",
    "build_capture_backend",
    "extract_domain_hint",
    "extract_flow_hints",
    "extract_ja4_fingerprint",
    "preflight_exit_code",
    "print_preflight_report",
    "run_preflight",
    "serialize_preflight_results",
]
