"""
Agent enrollment and registration management.
"""

import json
import logging
import platform
import time
from datetime import datetime
from typing import Dict, Any, Optional

import requests
from colorama import Fore, Style

from agent.security import AgentApiClient
from shared.collector import compute_machine_fingerprint

logger = logging.getLogger(__name__)


class EnrollmentManager:
    """Handles agent registration, enrollment, and credential management."""
    
    def __init__(
        self,
        agent_id: str,
        hostname: str,
        local_ip: str,
        local_mac: str,
        organization_id: str,
        api_client: AgentApiClient,
        heartbeat_url: str,
        agent_version: str = "v3.0-hybrid",
        retry_seconds: int = 15
    ):
        self.agent_id = agent_id
        self.hostname = hostname
        self.local_ip = local_ip
        self.local_mac = local_mac
        self.organization_id = organization_id
        self.api_client = api_client
        self.heartbeat_url = heartbeat_url
        self.agent_version = agent_version
        self.retry_seconds = retry_seconds
        
        self._enrollment_pending = False
        self._enrollment_status = "unknown"
        self._enrollment_message = None
        
    @property
    def enrollment_status(self) -> str:
        return self._enrollment_status
        
    @property
    def enrollment_pending(self) -> bool:
        return self._enrollment_pending
        
    @property
    def enrollment_message(self) -> Optional[str]:
        return self._enrollment_message
        
    def register_agent(self, *, force_reenroll: bool = False) -> Optional[Dict[str, Any]]:
        """Register agent with the backend server."""
        retry_delay = 1
        
        while True:  # Will be broken by return or exception
            try:
                payload = {
                    "agent_id": self.agent_id,
                    "hostname": self.hostname,
                    "os": platform.system(),
                    "version": self.agent_version,
                    "device_ip": self.local_ip,
                    "device_mac": self.local_mac,
                    "time": datetime.now().isoformat(),
                    "organization_id": self.organization_id,
                    "reenroll": bool(force_reenroll),
                    "machine_fingerprint": compute_machine_fingerprint(self.organization_id),
                }
                
                r = self.api_client.bootstrap_post(
                    self.heartbeat_url.replace("/heartbeat", "/register"),
                    json_body=payload,
                    timeout=5,
                    reenroll=force_reenroll,
                )
                
                try:
                    r.raise_for_status()
                except requests.HTTPError:
                    response_payload = {}
                    try:
                        response_payload = r.json()
                    except ValueError:
                        response_payload = {}
                    
                    enrollment_status = str(response_payload.get("enrollment_status") or "").strip().lower()
                    if r.status_code in {403, 409}:
                        if enrollment_status in {"credential_expired", "credential_rotated"}:
                            logger.info(f"Credential {enrollment_status}. Auto re-enrolling.")
                            # Break out and let await_enrollment or heartbeat handle it if we are already in force_reenroll
                            # But wait, if force_reenroll is False, we can retry with force_reenroll=True
                            if not force_reenroll:
                                force_reenroll = True
                                continue
                                
                        if enrollment_status in {"rejected", "revoked"}:
                            self._enrollment_pending = False
                            self._enrollment_status = enrollment_status or "rejected"
                            self._enrollment_message = (
                                response_payload.get("message")
                                or response_payload.get("detail")
                                or "Agent enrollment was rejected."
                            )
                            raise RuntimeError(self._enrollment_message)
                    raise
                    
                res = r.json()
                enrollment_status = str(res.get("enrollment_status") or "").strip().lower()
                
                # Update organization ID if provided by server
                if res.get("organization_id"):
                    self.organization_id = res["organization_id"]
                
                if enrollment_status == "pending_review":
                    self._enrollment_pending = True
                    self._enrollment_status = enrollment_status
                    self._enrollment_message = res.get("message") or "Enrollment pending admin approval."
                    self.retry_seconds = max(int(res.get("enrollment_next_retry_seconds") or self.retry_seconds), 1)
                    print(f"{Fore.YELLOW}[!] {self._enrollment_message}{Style.RESET_ALL}")
                    return res
                    
                # Check if we have valid credentials
                has_credentials = self.api_client.has_credentials()
                if not has_credentials:
                    raise RuntimeError(
                        "Agent registration did not yield signed credentials and no stored credential is available. "
                        "This agent requires explicit credential rotation or re-enrollment before it can continue."
                    )
                    
                self._enrollment_pending = False
                self._enrollment_status = "approved"
                self._enrollment_message = res.get("message")
                
                if force_reenroll:
                    print(f"{Fore.GREEN}[+] Agent re-enrolled: {self.agent_id}")
                else:
                    print(f"{Fore.GREEN}[+] Hybrid Flow Agent Registered: {self.agent_id}")
                    
                return res
                
            except RuntimeError:
                raise
            except Exception as e:
                logger.warning(f"Registration failed: {e}. Retrying...")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 30)
                
    def await_enrollment(self) -> Optional[str]:
        """Wait for enrollment to complete (for pending approval cases)."""
        while self._enrollment_pending or not self.api_client.has_credentials():
            result = self.register_agent(force_reenroll=not self.api_client.has_credentials())
            if not result:
                continue
                
            enrollment_status = str(result.get("enrollment_status") or "").strip().lower()
            if enrollment_status == "pending_review":
                sleep_seconds = max(int(result.get("enrollment_next_retry_seconds") or self.retry_seconds), 1)
                time.sleep(min(sleep_seconds, 60))
                continue
                
            break
            
        return self.organization_id
        
    def update_organization_id(self, organization_id: str) -> None:
        """Update the organization ID (typically from heartbeat response)."""
        self.organization_id = organization_id
