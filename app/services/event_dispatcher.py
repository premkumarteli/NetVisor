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
                    self._threat_worker(batch_data),
                    self._db_writer_worker(batch_data),
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

    async def _threat_worker(self, batch_data: dict) -> None:
        """Worker to run threat/risk rules and write alerts to database/memory store."""
        flows = batch_data.get("flows", [])
        org_id = batch_data.get("org_id") or "default"
        
        # Threat analysis is CPU/IO bound (queries DB, runs rules), run in thread
        await asyncio.to_thread(self._sync_threat_analysis, flows, org_id)

    def _sync_threat_analysis(self, flows: list, org_id: str) -> None:
        from ..engines.registry import EngineRegistry
        registry = EngineRegistry()
        
        conn = get_db_connection()
        if not conn:
            return
        cursor = None
        try:
            cursor = conn.cursor(dictionary=True)
            for flow_dict in flows:
                # Reconstruct flow dict into a dummy object/namespace for sanitization compatibility
                class DummyFlow:
                    def __init__(self, d):
                        for k, v in d.items():
                            setattr(self, k, v)
                
                flow_obj = DummyFlow(flow_dict)
                sanitized = flow_sanitization_service.sanitize_flow(flow_obj, organization_id=org_id)
                if not sanitized:
                    continue
                
                # Analyze using threat engines
                report = registry.analyze(sanitized, sanitized.last_seen)
                
                if sanitized.internal_device_ip:
                    # Update device risks in MySQL
                    cursor.execute(
                        """
                        INSERT INTO device_risks (device_id, organization_id, current_score, risk_level, reasons)
                        VALUES (%s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                            current_score = VALUES(current_score),
                            risk_level = VALUES(risk_level),
                            reasons = VALUES(reasons)
                        """,
                        (
                            sanitized.internal_device_ip,
                            org_id,
                            report["score"],
                            report["severity"],
                            ",".join(report["reasons"]),
                        ),
                    )

                
                # Check for high/critical threats to trigger alerts
                if sanitized.internal_device_ip and report["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]:
                    # Create breakdown
                    breakdown = report.get("breakdown", {})
                    if "message" not in breakdown:
                        breakdown["message"] = ", ".join(report["reasons"]) or "Suspicious activity detected"
                        
                    # Write to database alerts table
                    cursor.execute(
                        """
                        INSERT INTO alerts (organization_id, device_ip, severity, risk_score, breakdown_json)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (
                            org_id,
                            sanitized.internal_device_ip,
                            report["severity"],
                            report["score"],
                            json.dumps(breakdown),
                        ),
                    )
                    alert_id = cursor.lastrowid
                    
                    alert_data = {
                        "id": alert_id or f"alert-{int(time.time() * 1000)}",
                        "severity": report["severity"],
                        "score": report["score"],
                        "src_ip": sanitized.internal_device_ip,
                        "time": sanitized.last_seen.isoformat(),
                        "message": breakdown["message"]
                    }
                    
                    # Record in in-memory live store
                    live_telemetry_store.record_alert(org_id, alert_data)
                    
                    # Log audit and emit alert_event immediately
                    logger.info("Threat Worker Alert Created: %s", alert_data)
                    try:
                        from app.middleware.prometheus_middleware import ALERTS_GENERATED
                        ALERTS_GENERATED.labels(severity=alert_data.get("severity", "INFO")).inc()
                    except ImportError:
                        pass
            conn.commit()
        except Exception:
            conn.rollback()
            logger.exception("Error in Threat Worker sync analysis")
        finally:
            if cursor:
                cursor.close()
            conn.close()

    async def _db_writer_worker(self, batch_data: dict) -> None:
        """Worker to persist flow batch records to historical database storage (MySQL)."""
        flows = batch_data.get("flows", [])
        org_id = batch_data.get("org_id") or "default"
        agent_id = batch_data.get("agent_id")
        source_type = batch_data.get("source_type") or "agent"
        
        # Heavy DB writes, run in thread
        await asyncio.to_thread(self._sync_db_write, flows, org_id, agent_id, source_type)

    def _sync_db_write(self, flows: list, org_id: str, agent_id: str, source_type: str) -> None:
        conn = get_db_connection()
        if not conn:
            return
        cursor = None
        try:
            cursor = conn.cursor(dictionary=True)
            for flow_dict in flows:
                class DummyFlow:
                    def __init__(self, d):
                        for k, v in d.items():
                            setattr(self, k, v)
                
                flow_obj = DummyFlow(flow_dict)
                sanitized = flow_sanitization_service.sanitize_flow(flow_obj, organization_id=org_id)
                if not sanitized:
                    continue
                
                # Check duplicate by hash
                cursor.execute("SELECT 1 FROM flow_logs WHERE ingest_hash = %s LIMIT 1", (sanitized.ingest_hash,))
                if cursor.fetchone():
                    continue
                
                # Resolve application
                application = application_service.resolve_application_label({
                    "application": sanitized.application_protocol,
                    "service_name": sanitized.service_name,
                    "sni": sanitized.sni,
                    "domain": sanitized.domain,
                    "dst_port": sanitized.dst_port,
                    "protocol": sanitized.protocol
                })
                
                # Determine session ID
                session_id = None
                
                # Insert flow record
                cursor.execute(
                    """
                    INSERT INTO flow_logs (
                        organization_id, src_ip, dst_ip, src_port, dst_port,
                        protocol, start_time, last_seen, packet_count, byte_count,
                        duration, average_packet_size, domain, sni, src_mac, dst_mac,
                        network_scope, flow_direction, internal_device_ip, external_endpoint_ip, session_id,
                        application, agent_id, analysis_source, analysis_confidence, analysis_signals_json,
                        ingest_hash
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        org_id,
                        sanitized.src_ip,
                        sanitized.dst_ip,
                        sanitized.src_port,
                        sanitized.dst_port,
                        sanitized.protocol,
                        sanitized.start_time.strftime("%Y-%m-%d %H:%M:%S") if sanitized.start_time else None,
                        sanitized.last_seen.strftime("%Y-%m-%d %H:%M:%S") if sanitized.last_seen else None,
                        sanitized.packet_count,
                        sanitized.byte_count,
                        sanitized.duration,
                        sanitized.average_packet_size,
                        sanitized.domain,
                        sanitized.sni,
                        sanitized.src_mac,
                        sanitized.dst_mac,
                        sanitized.network_scope,
                        sanitized.flow_direction,
                        sanitized.internal_device_ip,
                        sanitized.external_endpoint_ip,
                        session_id,
                        application or "Other",
                        agent_id,
                        sanitized.analysis_source,
                        sanitized.analysis_confidence,
                        json.dumps(list(sanitized.analysis_signals)),
                        sanitized.ingest_hash
                    ),
                )
                
                # Record device in devices inventory table
                if sanitized.internal_device_ip:
                    device_service.touch_device_seen(
                        conn,
                        ip=sanitized.internal_device_ip,
                        organization_id=org_id,
                        seen_at=sanitized.last_seen,
                        agent_id=agent_id if source_type == "agent" else None,
                        mac=sanitized.internal_device_mac,
                        create_if_missing=(source_type == "agent" and bool(sanitized.internal_device_mac)),
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            logger.exception("Error in DB Writer sync persistence")
        finally:
            if cursor:
                cursor.close()
            conn.close()

    async def _audit_worker(self, batch_data: dict) -> None:
        """Worker to audit processing metrics."""
        flows = batch_data.get("flows", [])
        org_id = batch_data.get("org_id") or "default"
        logger.debug("Audit Event Worker: Processed batch of %d flows for org %s.", len(flows), org_id)

# Global singleton event dispatcher
event_dispatcher = EventDispatcher()
