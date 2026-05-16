import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, List

from agent.security import AgentApiClient

logger = logging.getLogger(__name__)

class TelemetryManager:
    def __init__(
        self,
        api_client: AgentApiClient,
        telemetry_url: str,
        upload_interval_seconds: int = 60,
        max_buffer_size: int = 1000
    ):
        self.api_client = api_client
        self.telemetry_url = telemetry_url
        self.upload_interval_seconds = upload_interval_seconds
        self.max_buffer_size = max_buffer_size
        self.buffer: List[Dict[str, Any]] = []
        self.buffer_lock = threading.Lock()
        self.is_running = True
        self.enabled = True

    def start(self):
        threading.Thread(target=self._worker, daemon=True).start()

    def stop(self):
        self.is_running = False
        self._flush()

    def update_config(self, enabled: bool, interval: int):
        self.enabled = enabled
        self.upload_interval_seconds = interval

    def log(self, level: str, category: str, message: str, metadata: Dict[str, Any] = None):
        if not self.enabled:
            return
            
        with self.buffer_lock:
            if len(self.buffer) >= self.max_buffer_size:
                self.buffer.pop(0)  # Evict oldest if full
                
            self.buffer.append({
                "log_level": level,
                "category": category,
                "message": message,
                "metadata": metadata or {},
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

    def _worker(self):
        while self.is_running:
            time.sleep(self.upload_interval_seconds)
            if self.enabled:
                self._flush()

    def _flush(self):
        if not self.api_client.has_credentials():
            return
            
        with self.buffer_lock:
            if not self.buffer:
                return
            batch = self.buffer.copy()
            self.buffer.clear()

        try:
            response = self.api_client.request(
                "POST", 
                self.telemetry_url, 
                json_body={"logs": batch},
                timeout=10
            )
            response.raise_for_status()
        except Exception as e:
            logger.debug(f"Failed to upload telemetry batch: {e}")
            # Re-queue on failure if we have space
            with self.buffer_lock:
                space_left = self.max_buffer_size - len(self.buffer)
                if space_left > 0:
                    self.buffer = batch[:space_left] + self.buffer
