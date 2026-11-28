"""High-throughput gRPC HTTP/2 telemetry ingestion service for NetVisor.

Provides streaming and unary RPC endpoints for low-overhead flow ingestion directly
from probe agents, dispatching into the SEDA worker pool or FlowService.
"""

from __future__ import annotations

import logging
import time
from typing import Any, AsyncIterator, Optional

import grpc

try:
    from backend.proto import flow_telemetry_pb2, flow_telemetry_pb2_grpc
except ImportError:
    import flow_telemetry_pb2  # type: ignore
    import flow_telemetry_pb2_grpc  # type: ignore

from backend.utils.protobuf_serializer import flow_pb_to_dict

logger = logging.getLogger(__name__)


class FlowIngestionServicer(flow_telemetry_pb2_grpc.FlowIngestionServiceServicer):
    """gRPC Servicer handling FlowIngestionService RPC calls."""

    def __init__(self, seda_pool: Optional[Any] = None) -> None:
        self._seda_pool = seda_pool
        self._total_ingested = 0

    async def StreamFlows(
        self,
        request_iterator: AsyncIterator[flow_telemetry_pb2.FlowTelemetryBatch],
        context: grpc.aio.ServicerContext,
    ) -> flow_telemetry_pb2.IngestionResponse:
        """Bidirectional / client-streaming RPC accepting continuous telemetry batches."""
        accepted = 0
        try:
            async for batch in request_iterator:
                count = len(batch.flows)
                if self._seda_pool:
                    # Submit binary protobuf bytes directly into SEDA Ingress Stage
                    payload_bytes = batch.SerializeToString()
                    self._seda_pool.submit_batch(payload_bytes)
                accepted += count
                self._total_ingested += count

            return flow_telemetry_pb2.IngestionResponse(
                success=True,
                accepted_count=accepted,
                message=f"Successfully ingested {accepted} flows via HTTP/2 gRPC stream.",
                processed_epoch_ms=int(time.time() * 1000),
            )
        except Exception as exc:
            logger.error("gRPC StreamFlows error: %s", exc, exc_info=True)
            return flow_telemetry_pb2.IngestionResponse(
                success=False,
                accepted_count=accepted,
                message=f"Stream ingestion aborted: {exc}",
                processed_epoch_ms=int(time.time() * 1000),
            )

    async def IngestBatch(
        self,
        request: flow_telemetry_pb2.FlowTelemetryBatch,
        context: grpc.aio.ServicerContext,
    ) -> flow_telemetry_pb2.IngestionResponse:
        """Unary RPC accepting a single FlowTelemetryBatch."""
        try:
            count = len(request.flows)
            if self._seda_pool:
                payload_bytes = request.SerializeToString()
                self._seda_pool.submit_batch(payload_bytes)
            self._total_ingested += count

            return flow_telemetry_pb2.IngestionResponse(
                success=True,
                accepted_count=count,
                message=f"Batch of {count} flows ingested.",
                processed_epoch_ms=int(time.time() * 1000),
            )
        except Exception as exc:
            logger.error("gRPC IngestBatch error: %s", exc, exc_info=True)
            return flow_telemetry_pb2.IngestionResponse(
                success=False,
                accepted_count=0,
                message=f"Batch ingestion failed: {exc}",
                processed_epoch_ms=int(time.time() * 1000),
            )


def create_grpc_server(
    host: str = "0.0.0.0",
    port: int = 50051,
    seda_pool: Optional[Any] = None,
) -> grpc.aio.Server:
    """Instantiates and registers a gRPC async server for FlowIngestionService."""
    server = grpc.aio.server(
        options=[
            ("grpc.max_receive_message_length", 64 * 1024 * 1024),  # 64 MB
            ("grpc.max_send_message_length", 64 * 1024 * 1024),
            ("grpc.http2.max_pings_without_data", 0),
            ("grpc.keepalive_time_ms", 30000),
            ("grpc.keepalive_timeout_ms", 10000),
        ]
    )
    servicer = FlowIngestionServicer(seda_pool=seda_pool)
    flow_telemetry_pb2_grpc.add_FlowIngestionServiceServicer_to_server(servicer, server)
    server.add_insecure_port(f"{host}:{port}")
    return server
