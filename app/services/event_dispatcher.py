import asyncio
import logging
import time
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import mysql.connector

from .live_telemetry_store import live_telemetry_store
from .flow_sanitization_service import flow_sanitization_service
from .device_service import device_service
from .application_service import application_service
from .external_endpoint_service import external_endpoint_service
from ..db.session import get_db_connection
from ..schemas.flow_schema import FlowBase
from ..realtime import emit_event

logger = logging.getLogger("netvisor.services.event_dispatcher")

# In-process queue for incoming flow telemetry batches
flow_ingestion_queue = asyncio.Queue(maxsize=5000)

class TelemetryEvent:
    def __init__(self, event_type: str, org_id: str, payload: dict):
        self.event_type = event_type
        self.org_id = org_id
        self.payload = payload

class EventDispatcher:
    def __init__(self):
        self._running = False
        self._task = None

    def start(self) -> None:
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._loop())
            logger.info("Event Dispatcher Event Bus started.")

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            logger.info("Event Dispatcher Event Bus stopped.")

    async def _loop(self) -> None:
        while self._running:
            try:
                batch_data = await flow_ingestion_queue.get()
                # Run the workers concurrently
                await asyncio.gather(
                    self._metrics_worker(batch_data),
                    self._audit_worker(batch_data),
                    return_exceptions=True
                )
                flow_ingestion_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception("Error in Event Dispatcher loop: %s", e)
                await asyncio.sleep(1)

    async def _metrics_worker(self, batch_data: dict) -> None:
        """Worker to update in-memory rolling counters and active lists in LiveTelemetryStore."""
        flows = batch_data.get("flows", [])
        org_id = batch_data.get("org_id") or "default"
        
        for flow in flows:
            # Determine application label
            app = flow.get("application_protocol") or flow.get("service_name") or "Other"
            proto = flow.get("protocol") or "UNKNOWN"
            
            # Extract parameters for LiveTelemetryStore
            flow_key = (flow.get("src_ip"), flow.get("dst_ip"), int(flow.get("src_port") or 0), int(flow.get("dst_port") or 0), proto)
            bytes_count = int(flow.get("byte_count") or 0)
            packets_count = int(flow.get("packet_count") or 0)
            
            event_type = str(flow.get("event_type") or "FLOW_UPDATE").upper()
            
            # Record flow details
            live_telemetry_store.record_flow(
                organization_id=org_id,
                flow_key=flow_key,
                bytes_count=bytes_count,
                packets_count=packets_count,
                app=app,
                proto=proto,
                is_new=(event_type == "FLOW_NEW"),
                is_end=(event_type == "FLOW_END")
            )
            
            # Record device seen
            src_ip = flow.get("src_ip")
            if src_ip:
                live_telemetry_store.record_device_seen(org_id, src_ip)

    async def _audit_worker(self, batch_data: dict) -> None:
        """Worker to audit processing metrics."""
        flows = batch_data.get("flows", [])
        org_id = batch_data.get("org_id") or "default"
        logger.debug("Audit Event Worker: Processed batch of %d flows for org %s.", len(flows), org_id)

# Global singleton event dispatcher
event_dispatcher = EventDispatcher()
