import time
import json
import secrets
import hashlib
import hmac
import httpx
import logging

# Resolve root import
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from shared.security.agent_auth import sign_request
from app.core.config import settings

logger = logging.getLogger("netvisor.replay.sender")

class ReplaySender:
    """Manages secure derived key signature and HTTP POST telemetry transmission."""
    
    def __init__(self, agent_id: str, key_version: int, master_key: str):
        self.agent_id = agent_id
        self.key_version = key_version
        self.master_key = master_key
        
        # Derive agent-specific secret
        self.secret_salt = secrets.token_hex(32)
        self.agent_secret = self._derive_secret()
        self.secret_hash = hashlib.sha256(self.agent_secret.encode("utf-8")).hexdigest()
        
    def _derive_secret(self) -> str:
        material = f"{self.agent_id}:{self.key_version}:{self.secret_salt}".encode("utf-8")
        derived = hmac.new(self.master_key.encode("utf-8"), material, hashlib.sha256).digest()
        return derived.hex()

    async def send_batch(self, client: httpx.AsyncClient, flows: list, url: str) -> float:
        body = json.dumps(flows)
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        
        # Cryptographically sign request
        signature = sign_request(
            secret=self.agent_secret,
            method="POST",
            path="/api/v1/collect/flow/batch",
            timestamp=timestamp,
            nonce=nonce,
            body=body
        )
        
        headers = {
            "Content-Type": "application/json",
            "X-Agent-Id": self.agent_id,
            "X-NetVisor-Key-Version": str(self.key_version),
            "X-NetVisor-Timestamp": timestamp,
            "X-NetVisor-Nonce": nonce,
            "X-NetVisor-Signature": signature,
            "X-Protocol-Version": "1.0.0"
        }
        
        start_time = time.perf_counter()
        try:
            response = await client.post(url, headers=headers, content=body, timeout=10.0)
            duration = time.perf_counter() - start_time
            if response.status_code != 202:
                logger.error(f"Ingestion failed status={response.status_code} text={response.text}")
                return -1.0
            return duration
        except Exception as e:
            logger.error(f"Request exception: {e}")
            return -1.0
