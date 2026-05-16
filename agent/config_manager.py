import logging
import threading
import time
from typing import Callable, Dict, Any, Optional

from agent.security import AgentApiClient

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(
        self,
        api_client: AgentApiClient,
        config_url: str,
        poll_interval_seconds: int = 60,
        on_config_changed: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.api_client = api_client
        self.config_url = config_url
        self.poll_interval_seconds = poll_interval_seconds
        self.on_config_changed = on_config_changed
        self.current_config: Dict[str, Any] = {}
        self.is_running = True

    def start(self):
        threading.Thread(target=self._worker, daemon=True).start()
        
    def stop(self):
        self.is_running = False

    def _worker(self):
        # Initial wait to let heartbeat/enrollment finish
        time.sleep(5)
        while self.is_running:
            try:
                self._poll_config()
            except Exception as e:
                logger.debug(f"Config sync failed: {e}")
            time.sleep(self.poll_interval_seconds)

    def _poll_config(self):
        if not self.api_client.has_credentials():
            return
            
        try:
            response = self.api_client.request("GET", self.config_url, timeout=5)
            response.raise_for_status()
            data = response.json()
            
            if data.get("status") == "success" and "config" in data:
                new_config = data["config"]
                if new_config != self.current_config:
                    logger.info("Agent configuration updated from remote")
                    self.current_config = new_config
                    if self.on_config_changed:
                        self.on_config_changed(new_config)
        except Exception as e:
            logger.debug(f"Error fetching remote configuration: {e}")

    def get_config(self) -> Dict[str, Any]:
        return self.current_config
