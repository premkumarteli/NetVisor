from __future__ import annotations

import time
from typing import Dict, Any


class NetVisorMetricsExporter:
    """
    Prometheus Telemetry & Metrics Exporter for NetVisor NDR Engine.
    Generates standard Prometheus text exposition format metrics.
    """

    def __init__(self) -> None:
        self.packets_total: int = 0
        self.flows_total: int = 0
        self.queue_depth: int = 0
        self.memory_bytes: int = 0
        self.tcp_streams_total: int = 0
        self.alerts_total: int = 0

    def update_metrics(
        self,
        packets: int = 0,
        flows: int = 0,
        queue_depth: int = 0,
        memory_bytes: int = 0,
        tcp_streams: int = 0,
        alerts: int = 0,
    ) -> None:
        self.packets_total = packets
        self.flows_total = flows
        self.queue_depth = queue_depth
        self.memory_bytes = memory_bytes
        self.tcp_streams_total = tcp_streams
        self.alerts_total = alerts

    def generate_prometheus_exposition(self) -> str:
        """Generates standard Prometheus Exposition format metrics payload."""
        lines = [
            "# HELP netvisor_packets_total Total number of packets captured and processed",
            "# TYPE netvisor_packets_total counter",
            f"netvisor_packets_total {self.packets_total}",
            "",
            "# HELP netvisor_flows_total Total active tracked network flows",
            "# TYPE netvisor_flows_total gauge",
            f"netvisor_flows_total {self.flows_total}",
            "",
            "# HELP netvisor_queue_depth Current ring buffer queue depth",
            "# TYPE netvisor_queue_depth gauge",
            f"netvisor_queue_depth {self.queue_depth}",
            "",
            "# HELP netvisor_memory_bytes Current memory usage of packet engine in bytes",
            "# TYPE netvisor_memory_bytes gauge",
            f"netvisor_memory_bytes {self.memory_bytes}",
            "",
            "# HELP netvisor_tcp_streams_total Total active reassembled TCP streams",
            "# TYPE netvisor_tcp_streams_total gauge",
            f"netvisor_tcp_streams_total {self.tcp_streams_total}",
            "",
            "# HELP netvisor_alerts_total Total threat detection alerts raised",
            "# TYPE netvisor_alerts_total counter",
            f"netvisor_alerts_total {self.alerts_total}",
            "",
        ]
        return "\n".join(lines)
