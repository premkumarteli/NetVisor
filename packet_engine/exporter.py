from __future__ import annotations

import json
import time
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("netvisor.packet_engine.exporter")


class FlowExporterPipeline:
    """
    Multi-Format Flow & Stream Telemetry Export Pipeline.
    Serializes aggregated NDR flows into JSONL, Parquet dictionaries, and streaming Kafka/Webhook events
    to bridge the sensor directly to downstream Threat Detection & Analytics engines.
    """

    def __init__(self, export_format: str = "jsonl") -> None:
        self.export_format = export_format.lower()
        self.exported_count = 0
        self.exported_bytes = 0

    def export_flow(self, flow_dict: Dict[str, Any]) -> str:
        """Serializes a FlowObservation dictionary into target export format."""
        self.exported_count += 1

        if self.export_format == "jsonl":
            serialized = json.dumps(flow_dict, separators=(",", ":")) + "\n"
            self.exported_bytes += len(serialized)
            return serialized
        elif self.export_format == "parquet_dict":
            # Flattened dictionary optimized for PyArrow / Polars Parquet schema
            flat = {
                "timestamp_iso": flow_dict.get("start_time"),
                "src_ip": flow_dict.get("src_ip"),
                "dst_ip": flow_dict.get("dst_ip"),
                "src_port": int(flow_dict.get("src_port", 0)),
                "dst_port": int(flow_dict.get("dst_port", 0)),
                "protocol": str(flow_dict.get("protocol")),
                "app_proto": str(flow_dict.get("application_protocol") or "UNKNOWN"),
                "bytes": int(flow_dict.get("byte_count", 0)),
                "packets": int(flow_dict.get("packet_count", 0)),
                "domain": flow_dict.get("domain") or "",
                "sni": flow_dict.get("sni") or "",
                "ja4": flow_dict.get("ja4") or "",
            }
            serialized = json.dumps(flat)
            self.exported_bytes += len(serialized)
            return serialized
        else:
            serialized = json.dumps(flow_dict)
            self.exported_bytes += len(serialized)
            return serialized

    def export_batch(self, flows: List[Dict[str, Any]]) -> List[str]:
        return [self.export_flow(f) for f in flows]

    @property
    def metrics(self) -> dict[str, int]:
        return {
            "exported_count": self.exported_count,
            "exported_bytes": self.exported_bytes,
        }
