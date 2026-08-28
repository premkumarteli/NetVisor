"""Unified Packet Engine for NetVisor: Handles low-level capture, 5-tuple parsing, DPI extraction, flow aggregation, and traffic classification."""

from .backend import CaptureBackend, LinuxRawSocketCaptureBackend, ScapyCaptureBackend, build_capture_backend
from .classifier import PacketAnalysis, analyze_packet
from .classifier_fast import classify_packet_tier_fast
from .diagnostics import PreflightResult, preflight_exit_code, print_preflight_report, run_preflight, serialize_preflight_results
from .flow_aggregator import FlowKey, FlowManager, FlowState, FlowSummary
from .http_consumer import HttpStreamConsumer, HttpTransaction
from .metadata import DomainHintCache, extract_domain_hint, extract_flow_hints, extract_ja4_fingerprint
from .parser import DpiObservation, FlowObservation, PacketObservation
from .quic_parser import QuicMetadata, extract_quic_metadata
from .ring_buffer import DualRingBuffer, RawPacketEnvelope, wfq_worker_drain_loop
from .stream_registry import CONFIDENCE_MATRIX, StreamConsumerRegistry
from .tcp_stream import TCPStreamBuffer, TCPStreamStateEnum, TCPStreamTrackerManager
from .tls_consumer import TLSHandshakeMetadata, TlsStreamConsumer

__all__ = [
    "CONFIDENCE_MATRIX",
    "CaptureBackend",
    "DomainHintCache",
    "DpiObservation",
    "DualRingBuffer",
    "FlowKey",
    "FlowManager",
    "FlowObservation",
    "FlowState",
    "FlowSummary",
    "HttpStreamConsumer",
    "HttpTransaction",
    "LinuxRawSocketCaptureBackend",
    "PacketAnalysis",
    "PacketObservation",
    "PreflightResult",
    "QuicMetadata",
    "RawPacketEnvelope",
    "ScapyCaptureBackend",
    "StreamConsumerRegistry",
    "TCPStreamBuffer",
    "TCPStreamStateEnum",
    "TCPStreamTrackerManager",
    "TLSHandshakeMetadata",
    "TlsStreamConsumer",
    "analyze_packet",
    "build_capture_backend",
    "classify_packet_tier_fast",
    "extract_domain_hint",
    "extract_flow_hints",
    "extract_ja4_fingerprint",
    "extract_quic_metadata",
    "preflight_exit_code",
    "print_preflight_report",
    "run_preflight",
    "serialize_preflight_results",
    "wfq_worker_drain_loop",
]
