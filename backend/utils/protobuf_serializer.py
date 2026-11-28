"""High-performance Protobuf v3 serialization utility for NetVisor telemetry.

Provides bidirectional translation between native Python dictionary flow representations
and Protobuf v3 binary wire format, yielding a ~60-70% payload size reduction vs raw JSON.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Tuple

try:
    from backend.proto import flow_telemetry_pb2
except ImportError:
    import flow_telemetry_pb2  # type: ignore

logger = logging.getLogger(__name__)


def flow_dict_to_pb(flow: Dict[str, Any]) -> flow_telemetry_pb2.FlowRecord:
    """Converts a standard flow dictionary into a Protobuf FlowRecord."""
    rec = flow_telemetry_pb2.FlowRecord()
    rec.flow_id = str(flow.get("flow_id") or flow.get("id") or "")
    
    ts = flow.get("timestamp_epoch_ms")
    if ts is None:
        raw_ts = flow.get("timestamp") or flow.get("time") or time.time()
        if isinstance(raw_ts, (int, float)):
            rec.timestamp_epoch_ms = int(raw_ts * 1000) if raw_ts < 1e11 else int(raw_ts)
        else:
            rec.timestamp_epoch_ms = int(time.time() * 1000)
    else:
        rec.timestamp_epoch_ms = int(ts)

    rec.agent_id = str(flow.get("agent_id") or "")
    rec.device_id = str(flow.get("device_id") or "")
    rec.src_ip = str(flow.get("src_ip") or flow.get("source_ip") or "")
    rec.dst_ip = str(flow.get("dst_ip") or flow.get("dest_ip") or flow.get("destination_ip") or "")
    
    try:
        rec.src_port = int(flow.get("src_port") or flow.get("source_port") or 0)
    except (ValueError, TypeError):
        rec.src_port = 0

    try:
        rec.dst_port = int(flow.get("dst_port") or flow.get("dest_port") or flow.get("destination_port") or 0)
    except (ValueError, TypeError):
        rec.dst_port = 0

    rec.protocol = str(flow.get("protocol") or "TCP").upper()
    
    try:
        rec.packets = int(flow.get("packets") or flow.get("packet_count") or 1)
    except (ValueError, TypeError):
        rec.packets = 1

    try:
        rec.bytes = int(flow.get("bytes") or flow.get("byte_count") or 0)
    except (ValueError, TypeError):
        rec.bytes = 0

    rec.direction = str(flow.get("direction") or "outbound")
    rec.flags = str(flow.get("flags") or "")
    rec.threat_indicator = str(flow.get("threat_indicator") or "")
    rec.dns_query = str(flow.get("dns_query") or flow.get("domain") or "")
    rec.tls_sni = str(flow.get("tls_sni") or flow.get("sni") or "")
    rec.vpn_detected = bool(flow.get("vpn_detected") or False)
    rec.vpn_provider = str(flow.get("vpn_provider") or "")
    
    try:
        rec.risk_score = float(flow.get("risk_score") or 0.0)
    except (ValueError, TypeError):
        rec.risk_score = 0.0

    meta = flow.get("metadata")
    if isinstance(meta, dict):
        for k, v in meta.items():
            rec.metadata[str(k)] = str(v)

    return rec


def flow_pb_to_dict(rec: flow_telemetry_pb2.FlowRecord) -> Dict[str, Any]:
    """Converts a Protobuf FlowRecord into a standard dictionary."""
    return {
        "flow_id": rec.flow_id,
        "timestamp_epoch_ms": rec.timestamp_epoch_ms,
        "agent_id": rec.agent_id,
        "device_id": rec.device_id,
        "src_ip": rec.src_ip,
        "dst_ip": rec.dst_ip,
        "src_port": rec.src_port,
        "dst_port": rec.dst_port,
        "protocol": rec.protocol,
        "packets": rec.packets,
        "bytes": rec.bytes,
        "direction": rec.direction,
        "flags": rec.flags,
        "threat_indicator": rec.threat_indicator,
        "dns_query": rec.dns_query,
        "tls_sni": rec.tls_sni,
        "vpn_detected": rec.vpn_detected,
        "vpn_provider": rec.vpn_provider,
        "risk_score": rec.risk_score,
        "metadata": dict(rec.metadata),
    }


def serialize_flow_batch(
    flows: List[Dict[str, Any]],
    batch_id: str = "",
    agent_id: str = "",
) -> bytes:
    """Serializes a batch of flow dicts into binary Protobuf bytes."""
    batch = flow_telemetry_pb2.FlowTelemetryBatch()
    batch.batch_id = batch_id or f"batch_{int(time.time() * 1000)}"
    batch.agent_id = agent_id or ""
    batch.sent_epoch_ms = int(time.time() * 1000)

    for flow in flows:
        if isinstance(flow, dict):
            batch.flows.append(flow_dict_to_pb(flow))

    return batch.SerializeToString()


def deserialize_flow_batch(data: bytes | str) -> Dict[str, Any]:
    """Deserializes binary Protobuf bytes or JSON string into a batch dictionary.

    Returns dict with keys: 'batch_id', 'agent_id', 'sent_epoch_ms', 'flows'.
    """
    if isinstance(data, str):
        # JSON string fallback
        try:
            parsed = json.loads(data)
            if isinstance(parsed, list):
                return {
                    "batch_id": f"batch_{int(time.time() * 1000)}",
                    "agent_id": "",
                    "sent_epoch_ms": int(time.time() * 1000),
                    "flows": parsed,
                }
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            # Maybe it's hex-encoded protobuf bytes
            try:
                data = bytes.fromhex(data)
            except Exception:
                raise ValueError("Payload is neither valid JSON nor hex-encoded Protobuf.")

    # Try Protobuf decode first
    try:
        batch = flow_telemetry_pb2.FlowTelemetryBatch()
        batch.ParseFromString(data)
        flows = [flow_pb_to_dict(rec) for rec in batch.flows]
        return {
            "batch_id": batch.batch_id,
            "agent_id": batch.agent_id,
            "sent_epoch_ms": batch.sent_epoch_ms,
            "flows": flows,
        }
    except Exception as pb_err:
        # Fallback to UTF-8 JSON bytes
        try:
            parsed = json.loads(data.decode("utf-8"))
            if isinstance(parsed, list):
                return {
                    "batch_id": f"batch_{int(time.time() * 1000)}",
                    "agent_id": "",
                    "sent_epoch_ms": int(time.time() * 1000),
                    "flows": parsed,
                }
            return parsed
        except Exception:
            raise ValueError(f"Failed to decode payload as either Protobuf or JSON: {pb_err}")


def compare_wire_size(flows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Measures wire serialization sizes between JSON and Protobuf v3.

    Returns compression ratio, byte sizes, and reduction percentage.
    """
    json_bytes = json.dumps(flows, separators=(",", ":")).encode("utf-8")
    pb_bytes = serialize_flow_batch(flows)

    json_len = len(json_bytes)
    pb_len = len(pb_bytes)
    reduction_pct = (1.0 - (pb_len / json_len)) * 100.0 if json_len > 0 else 0.0

    return {
        "flow_count": len(flows),
        "json_bytes": json_len,
        "protobuf_bytes": pb_len,
        "saved_bytes": json_len - pb_len,
        "reduction_percent": round(reduction_pct, 2),
    }
