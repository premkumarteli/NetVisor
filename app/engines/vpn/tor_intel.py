import logging
import threading
import requests
import ipaddress
from typing import Optional

logger = logging.getLogger(__name__)

# Seed list of known Tor exit IPs — used only when the live feed is unavailable
_TOR_SEED_IPS: frozenset[str] = frozenset({
    "185.220.101.1",
    "185.220.101.2",
    "185.220.101.34",
    "185.220.101.45",
    "51.15.43.205",
    "51.15.50.46",
    "109.70.100.2",
    "109.70.100.4",
    "2a0b:f4c2::1",  # IPv6 example
})

_TOR_FEED_URL = "https://check.torproject.org/exit-addresses"
_TOR_REFRESH_INTERVAL_SECONDS = 86400  # 24 hours

class TorIntelligence:
    """
    Maintains a live set of known Tor exit-node IPs.

    Fetches the Tor Project's exit-address list on startup and every 24 hours.
    Falls back to _TOR_SEED_IPS when offline or on parse errors.
    Thread-safe via a read/write lock pattern (RLock).
    """

    def __init__(self, start_thread: bool = True) -> None:
        self._exit_nodes: frozenset[str] = _TOR_SEED_IPS
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._refresh_loop,
            name="tor-intel-refresh",
            daemon=True,
        )
        if start_thread:
            self._thread.start()

    # ── public API ────────────────────────────────────────────────────────────

    def is_tor_exit(self, ip: str) -> bool:
        with self._lock:
            return ip in self._exit_nodes

    def node_count(self) -> int:
        with self._lock:
            return len(self._exit_nodes)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=0.5)

    # ── private helpers ───────────────────────────────────────────────────────

    def _refresh_loop(self) -> None:
        # Immediate first fetch on startup
        self._fetch_and_update()
        while not self._stop_event.wait(timeout=_TOR_REFRESH_INTERVAL_SECONDS):
            self._fetch_and_update()

    def _fetch_and_update(self) -> None:
        try:
            resp = requests.get(_TOR_FEED_URL, timeout=15)
            resp.raise_for_status()
            nodes = self._parse_exit_addresses(resp.text)
            if nodes:
                with self._lock:
                    self._exit_nodes = frozenset(nodes)
                logger.info("TorIntelligence: refreshed %d exit nodes", len(nodes))
            else:
                logger.warning("TorIntelligence: parsed 0 nodes; retaining previous set")
        except Exception as exc:
            logger.warning("TorIntelligence: fetch failed (%s); using seed list", exc)

    @staticmethod
    def _parse_exit_addresses(text: str) -> list[str]:
        """
        Parse the Tor Project exit-addresses file.

        Format (per line):
            ExitAddress <IP> <datetime>
        """
        ips: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("ExitAddress"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                candidate = parts[1]
                try:
                    ipaddress.ip_address(candidate)
                    ips.append(candidate)
                except ValueError:
                    pass
        return ips

# Singleton instance exported for both old services and new engines to share
tor_intel = TorIntelligence()
