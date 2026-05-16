"""
Data upload management for agent telemetry.
"""

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from agent.security import AgentApiClient
from shared.collector import DiskBackedBuffer

logger = logging.getLogger(__name__)


class UploadManager:
    """Manages batching and uploading of telemetry data to the backend."""
    
    def __init__(
        self,
        api_client: AgentApiClient,
        upload_url: str,
        buffer_db_path: Path,
        buffer_max_mb: int = 50,
        max_batch_size: int = 20,
        max_wait_seconds: int = 5,
        max_memory: int = 10000
    ):
        self.api_client = api_client
        self.upload_url = upload_url
        self.max_batch_size = max_batch_size
        self.max_wait_seconds = max_wait_seconds
        
        self.buffer = DiskBackedBuffer(
            db_path=buffer_db_path,
            max_memory=max_memory,
            max_disk_mb=buffer_max_mb
        )
        self.is_running = True

        # Upload health tracking
        self._upload_failures: int = 0
        self._upload_successes: int = 0
        self._consecutive_failures: int = 0
        self._last_upload_time: str | None = None
        self._last_upload_error: str | None = None
        
    def stop(self) -> None:
        """Stop the upload manager."""
        self.is_running = False
        self.buffer.close()
        
    def enqueue_record(self, record: Dict[str, Any]) -> bool:
        """Enqueue a record for upload."""
        success = self.buffer.enqueue(record)
        if not success:
            logger.warning("Failed to enqueue record to disk-backed buffer")
        return success
            
    def upload_worker(self) -> None:
        """Main upload loop running in a separate thread."""
        batch = []
        last_send = time.time()
        
        while self.is_running:
            try:
                # Apply exponential backoff if there are consecutive failures
                if self._consecutive_failures > 0:
                    backoff_time = min(2 ** self._consecutive_failures, 30)
                    time.sleep(backoff_time)
                
                # Drain from buffer
                records = self.buffer.drain(batch_size=self.max_batch_size - len(batch))
                if records:
                    batch.extend(records)
                else:
                    time.sleep(1.0) # wait if buffer empty
                    
                # Check if we should send the batch
                should_send = (
                    len(batch) >= self.max_batch_size or
                    (time.time() - last_send > self.max_wait_seconds and batch)
                )
                
                if should_send:
                    if self._send_batch(batch):
                        batch = []
                    else:
                        self.buffer.requeue_front(batch)
                        batch = []
                    last_send = time.time()
                    
            except Exception as e:
                logger.error(f"Upload worker error: {e}")
                # Add small backoff on error
                time.sleep(2)
                
    def _send_batch(self, batch: List[Dict[str, Any]]) -> bool:
        """Send a batch of records to the server."""
        try:
            response = self.api_client.request("POST", self.upload_url, json_body=batch, timeout=10.0)
            response.raise_for_status()
            logger.debug(f"Successfully uploaded batch of {len(batch)} records")
            self._upload_successes += 1
            self._consecutive_failures = 0
            self._last_upload_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            self._last_upload_error = None
            return True
        except Exception as e:
            logger.error(f"Batch upload failed: {e}")
            self._upload_failures += 1
            self._consecutive_failures += 1
            self._last_upload_error = str(e)
            return False
            
    def get_queue_depth(self) -> int:
        """Get the current queue depth."""
        return self.buffer.pending_count

    def health_snapshot(self) -> Dict[str, Any]:
        """Get upload health metrics for heartbeat reporting."""
        return {
            "upload_failures": self._upload_failures,
            "upload_successes": self._upload_successes,
            "last_upload_time": self._last_upload_time,
            "last_upload_error": self._last_upload_error,
            "queue_depth": self.buffer.pending_count,
            "consecutive_failures": self._consecutive_failures,
            "buffer_disk_usage_bytes": self.buffer.disk_usage_bytes,
        }
