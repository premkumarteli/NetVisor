"""
Agent heartbeat and health monitoring.
"""

import json
import logging
import platform
import time
from datetime import datetime
from typing import Dict, Any, Optional

try:
    import psutil
except ImportError:
    psutil = None

import requests

from agent.enrollment import EnrollmentManager
from agent.security import AgentApiClient
from shared.collector.health import CollectorHealthReport

logger = logging.getLogger(__name__)


class HeartbeatManager:
    """Manages agent health monitoring and periodic status reporting."""
    
    def __init__(
        self,
        agent_id: str,
        hostname: str,
        local_ip: str,
        local_mac: str,
        organization_id: str,
        api_client: AgentApiClient,
        heartbeat_url: str,
        enrollment_manager: EnrollmentManager,
        device_inventory_size_func,
        web_inspection_func,
        capture_health_func=None,
        upload_health_func=None,
        flow_health_func=None,
        organization_update_func=None,
        agent_version: str = "v3.0-hybrid",
        heartbeat_interval: int = 10
    ):
        self.agent_id = agent_id
        self.hostname = hostname
        self.local_ip = local_ip
        self.local_mac = local_mac
        self.organization_id = organization_id
        self.api_client = api_client
        self.heartbeat_url = heartbeat_url
        self.enrollment_manager = enrollment_manager
        self.device_inventory_size_func = device_inventory_size_func
        self.web_inspection_func = web_inspection_func
        self.capture_health_func = capture_health_func
        self.upload_health_func = upload_health_func
        self.flow_health_func = flow_health_func
        self.organization_update_func = organization_update_func
        self.agent_version = agent_version
        self.heartbeat_interval = heartbeat_interval
        self.is_running = True
        
    def stop(self) -> None:
        """Stop the heartbeat manager."""
        self.is_running = False

    def _build_collector_health(self) -> Dict[str, Any]:
        """Build a consolidated collector health report."""
        capture_snapshot = self.capture_health_func() if self.capture_health_func else {}
        upload_snapshot = self.upload_health_func() if self.upload_health_func else {}
        flow_snapshot = self.flow_health_func() if self.flow_health_func else {}

        report = CollectorHealthReport.build(
            capture_snapshot=capture_snapshot,
            upload_snapshot=upload_snapshot,
            flow_snapshot=flow_snapshot,
        )
        return report.to_dict()

    def _build_heartbeat_payload(self) -> Dict[str, Any]:
        """Build the heartbeat payload with system metrics."""
        if psutil:
            try:
                cpu = psutil.cpu_percent()
                ram = psutil.virtual_memory().percent
            except Exception:
                cpu = 0.0
                ram = 0.0
        else:
            cpu = 0.0
            ram = 0.0

        collector_health = self._build_collector_health()
        
        payload = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "os": platform.system(),
            "version": self.agent_version,
            "device_ip": self.local_ip,
            "device_mac": self.local_mac,
            "status": "online",
            "dropped_packets": 0,
            "cpu_usage": cpu,
            "ram_usage": ram,
            "inventory_size": self.device_inventory_size_func(),
            "time": datetime.now().isoformat(),
            "organization_id": self.organization_id,
            "web_inspection": self.web_inspection_func() or {},
            "capture_health": collector_health.get("capture_health", {}),
            "collector_health": collector_health,
        }
        
        return payload
        
    def send_heartbeat(self) -> Optional[str]:
        """Send a single heartbeat to the server."""
        try:
            # Ensure we have valid credentials before sending heartbeat
            if not self.api_client.has_credentials():
                self.enrollment_manager.register_agent(force_reenroll=True)
                
            payload = self._build_heartbeat_payload()
            response = self.api_client.request("POST", self.heartbeat_url, json_body=payload, timeout=5)
            response.raise_for_status()
            
            response_payload = response.json()
            
            # Update organization ID if provided by server
            if response_payload.get("organization_id"):
                new_org_id = response_payload["organization_id"]
                if new_org_id != self.organization_id:
                    self.organization_id = new_org_id
                    self.enrollment_manager.update_organization_id(new_org_id)
                    if self.organization_update_func:
                        self.organization_update_func(new_org_id)
                    
            return self.organization_id
            
        except requests.HTTPError as e:
            if e.response.status_code in {403, 409}:
                try:
                    err_payload = e.response.json()
                    status_reason = str(err_payload.get("enrollment_status") or err_payload.get("reason") or "").strip().lower()
                except ValueError:
                    status_reason = ""
                    
                if status_reason in {"credential_expired", "credential_rotated", "unknown_credential"}:
                    logger.warning("Heartbeat returned 403 expired credential. Triggering re-enrollment.")
                    self.enrollment_manager.register_agent(force_reenroll=True)
                elif status_reason in {"revoked", "wrong_organization"}:
                    logger.critical(f"Agent access revoked or invalid ({status_reason}). Stopping.")
                    self.stop()
                elif status_reason == "pending_review":
                    logger.info("Agent pending review. Pausing heartbeat.")
                else:
                    logger.warning(f"Heartbeat 403: {status_reason}")
            else:
                logger.warning(f"Heartbeat failed HTTP error: {e}")
            return None
        except Exception as e:
            logger.warning(f"Heartbeat failed: {e}")
            return None
            
    def heartbeat_worker(self) -> None:
        """Main heartbeat loop running in a separate thread."""
        while self.is_running:
            try:
                self.send_heartbeat()
            except Exception as e:
                logger.error(f"Heartbeat worker error: {e}")
                
            time.sleep(self.heartbeat_interval)

