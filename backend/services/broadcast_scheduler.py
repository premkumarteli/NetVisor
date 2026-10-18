import asyncio
import logging
import time
from .live_telemetry_store import live_telemetry_store
from ..realtime import emit_event

logger = logging.getLogger("netvisor.services.broadcast_scheduler")

class BroadcastScheduler:
    def __init__(self):
        self._running = False
        self._task = None
        self._tick_count = 0

    def start(self) -> None:
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._loop())
            logger.info("Broadcast Scheduler started.")

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            logger.info("Broadcast Scheduler stopped.")

    async def _loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(0.5)  # 500 ms tick rate
                await self.broadcast_all()
                self._tick_count += 1
                if self._tick_count >= 120:  # ~60 seconds
                    self._tick_count = 0
                    asyncio.create_task(self._sync_stale_devices())
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception("Error in Broadcast Scheduler loop: %s", e)

    async def _sync_stale_devices(self) -> None:
        try:
            from ..db.session import get_db_connection
            from .device_service import device_service

            def _sync():
                conn = None
                try:
                    conn = get_db_connection()
                    device_service.mark_stale_devices_offline(conn)
                finally:
                    if conn:
                        conn.close()

            await asyncio.to_thread(_sync)
        except Exception as exc:
            logger.debug("Periodic stale devices sync skipped/failed: %s", exc)

    async def broadcast_all(self) -> None:
        # Get active organization IDs from the live store
        # Protect dictionary mutation during iteration
        with live_telemetry_store._global_lock:
            org_ids = list(live_telemetry_store._states.keys())

        for org_id in org_ids:
            # Skip empty or internal keys unless needed
            stats = live_telemetry_store.get_overview_stats(org_id)
            recent_alerts = live_telemetry_store.get_recent_alerts(org_id, 12)
            
            payload = {
                "organization_id": org_id if org_id != "default" else None,
                "stats": stats,
                "recent_alerts": recent_alerts,
            }
            # Emit the centralized dashboard update event
            await emit_event("dashboard_update", payload)

# Global singleton scheduler instance
broadcast_scheduler = BroadcastScheduler()
