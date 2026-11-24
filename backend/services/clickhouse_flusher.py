import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Tuple

from backend.core.config import settings

logger = logging.getLogger("netvisor.services.clickhouse_flusher")

CLICKHOUSE_FLOW_COLUMNS: list[str] = [
    "organization_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "start_time",
    "last_seen",
    "packet_count",
    "byte_count",
    "duration",
    "average_packet_size",
    "domain",
    "sni",
    "src_mac",
    "dst_mac",
    "network_scope",
    "flow_direction",
    "internal_device_ip",
    "external_endpoint_ip",
    "session_id",
    "application",
    "agent_id",
    "analysis_source",
    "analysis_confidence",
    "analysis_signals_json",
    "ingest_hash",
]


class DiskSpoolWAL:
    """Append-only local disk spool circuit breaker for telemetry during ClickHouse outages."""

    def __init__(self, spool_dir: Optional[str] = None, max_files: int = 500) -> None:
        self.spool_path = Path(spool_dir or getattr(settings, "CLICKHOUSE_SPOOL_DIR", "data/spool/clickhouse"))
        self.max_files = max_files
        self._lock = threading.Lock()
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        try:
            self.spool_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning("Failed to create ClickHouse spool directory %s: %s", self.spool_path, e)

    def spool_batch(self, batch: List[Tuple[Any, ...]]) -> bool:
        """Serializes a batch of flow rows to an atomic .wal spool file on disk."""
        if not batch:
            return True

        with self._lock:
            try:
                self._ensure_dir()
                existing_wal = sorted(self.spool_path.glob("*.wal"))
                if len(existing_wal) >= self.max_files:
                    # Drop oldest WAL file to protect local disk capacity
                    oldest = existing_wal[0]
                    try:
                        oldest.unlink(missing_ok=True)
                        logger.warning("Spool capacity exceeded (%d files). Dropped oldest WAL: %s", self.max_files, oldest.name)
                    except Exception as drop_err:
                        logger.error("Error evicting oldest spool WAL: %s", drop_err)

                ts = int(time.time_ns())
                uid = uuid.uuid4().hex[:8]
                tmp_file = self.spool_path / f"spool_{ts}_{uid}.tmp"
                target_file = self.spool_path / f"spool_{ts}_{uid}.wal"

                # Serialize rows with ISO-formatted datetimes for reliable recovery
                serialized_rows = []
                for row in batch:
                    serialized_row = []
                    for item in row:
                        if isinstance(item, datetime):
                            serialized_row.append(item.isoformat())
                        else:
                            serialized_row.append(item)
                    serialized_rows.append(serialized_row)

                payload = {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "columns": CLICKHOUSE_FLOW_COLUMNS,
                    "rows": serialized_rows,
                }

                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(payload, f)
                    f.flush()
                    os.fsync(f.fileno())

                tmp_file.replace(target_file)
                logger.info("Spolled %d flows to local WAL circuit breaker: %s", len(batch), target_file.name)
                return True
            except Exception as exc:
                logger.error("Failed to spool flow batch to disk WAL: %s", exc)
                return False

    def pending_count(self) -> int:
        """Returns the number of pending .wal spool files awaiting replay."""
        try:
            return len(list(self.spool_path.glob("*.wal")))
        except Exception:
            return 0

    def drain_spool(self, client: Any, max_files: int = 10) -> int:
        """Replays and unlinks pending .wal files to ClickHouse when connection is restored."""
        with self._lock:
            try:
                wal_files = sorted(self.spool_path.glob("*.wal"))[:max_files]
                if not wal_files:
                    return 0

                total_drained = 0
                for wal_file in wal_files:
                    try:
                        with open(wal_file, "r", encoding="utf-8") as f:
                            data = json.load(f)

                        rows = data.get("rows", [])
                        if not rows:
                            wal_file.unlink(missing_ok=True)
                            continue

                        # Parse ISO timestamps back to datetime
                        deserialized_rows = []
                        for row in rows:
                            r = list(row)
                            # start_time is index 6, last_seen is index 7
                            for idx in (6, 7):
                                if idx < len(r) and isinstance(r[idx], str):
                                    try:
                                        r[idx] = datetime.fromisoformat(r[idx])
                                    except Exception:
                                        pass
                            deserialized_rows.append(tuple(r))

                        client.insert("flow_logs", deserialized_rows, column_names=CLICKHOUSE_FLOW_COLUMNS)
                        wal_file.unlink(missing_ok=True)
                        total_drained += len(deserialized_rows)
                        logger.info("Successfully drained %d flows from WAL %s into ClickHouse", len(deserialized_rows), wal_file.name)
                    except Exception as err:
                        logger.warning("Failed to drain spool WAL %s: %s", wal_file.name, err)
                        break  # Stop draining on first failure to preserve order

                return total_drained
            except Exception as e:
                logger.error("Error during spool drain: %s", e)
                return 0


class ClickHouseDoubleBufferFlusher:
    """
    High-Throughput Double-Buffered Columnar Ingestion Engine for NetVisor.

    Features:
    - Non-blocking in-memory accumulation of flow telemetry.
    - Zero-lock pointer swap on batch threshold (default 5,000 rows) or timer (default 1.0s).
    - Asynchronous multi-row insert into ClickHouse MergeTree.
    - Automatic local DiskSpoolWAL circuit breaker on network failure or maintenance.
    - Auto-replaying background spool drainer.
    """

    def __init__(
        self,
        batch_size: Optional[int] = None,
        flush_interval_seconds: Optional[float] = None,
        spool_dir: Optional[str] = None,
    ) -> None:
        self.batch_size = batch_size or getattr(settings, "CLICKHOUSE_FLUSH_BATCH_SIZE", 5000)
        self.flush_interval = flush_interval_seconds or getattr(settings, "CLICKHOUSE_FLUSH_INTERVAL_SECONDS", 1.0)
        self.spool = DiskSpoolWAL(spool_dir=spool_dir)

        self._active_buffer: List[Tuple[Any, ...]] = []
        self._lock = threading.Lock()
        self._flush_trigger = threading.Event()
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Starts the background flush and spool drain worker thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="netvisor-ch-flusher",
                daemon=True,
            )
            self._worker_thread.start()
            logger.info(
                "ClickHouseDoubleBufferFlusher started (BatchSize: %d, Interval: %.1fs)",
                self.batch_size,
                self.flush_interval,
            )

    def enqueue(self, rows: List[Tuple[Any, ...]]) -> None:
        """Appends flow rows to the active buffer; triggers swap if batch threshold reached."""
        if not rows:
            return

        should_trigger = False
        with self._lock:
            self._active_buffer.extend(rows)
            if len(self._active_buffer) >= self.batch_size:
                should_trigger = True

        if should_trigger:
            self._flush_trigger.set()

    def _swap_buffer(self) -> List[Tuple[Any, ...]]:
        """Atomically swaps active buffer with a new empty buffer under lock."""
        with self._lock:
            if not self._active_buffer:
                return []
            detached = self._active_buffer
            self._active_buffer = []
            return detached

    def _worker_loop(self) -> None:
        """Background flusher loop executing timed or threshold-triggered flushes."""
        last_flush_time = time.monotonic()

        while self._running:
            self._flush_trigger.wait(timeout=self.flush_interval)
            self._flush_trigger.clear()

            now = time.monotonic()
            if (now - last_flush_time) >= self.flush_interval or len(self._active_buffer) >= self.batch_size:
                detached = self._swap_buffer()
                if detached:
                    self._persist_chunk(detached)
                    last_flush_time = time.monotonic()

                # Opportunistically drain disk spool WAL if files exist
                if self.spool.pending_count() > 0:
                    self._try_drain_spool()

    def _persist_chunk(self, chunk: List[Tuple[Any, ...]]) -> bool:
        """Inserts a detached batch into ClickHouse with retry and WAL fallback."""
        if not chunk:
            return True

        from backend.db.clickhouse_client import get_clickhouse_client

        max_retries = 3
        retry_delay = 0.05

        for attempt in range(max_retries):
            try:
                client = get_clickhouse_client()
                t0 = time.perf_counter()
                client.insert("flow_logs", chunk, column_names=CLICKHOUSE_FLOW_COLUMNS)
                duration = time.perf_counter() - t0

                try:
                    from backend.middleware.prometheus_middleware import (
                        CLICKHOUSE_INSERT_LATENCY,
                        CLICKHOUSE_INSERT_ROWS,
                    )
                    CLICKHOUSE_INSERT_LATENCY.observe(duration)
                    CLICKHOUSE_INSERT_ROWS.inc(len(chunk))
                except Exception:
                    pass

                logger.debug("Successfully flushed %d flows to ClickHouse in %.3fs", len(chunk), duration)
                return True
            except Exception as exc:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                else:
                    logger.warning(
                        "ClickHouse insert failed after %d attempts (%s). Spilling to disk WAL.",
                        max_retries,
                        exc,
                    )
                    try:
                        from backend.middleware.prometheus_middleware import CLICKHOUSE_FAILED_WRITES
                        CLICKHOUSE_FAILED_WRITES.inc()
                    except Exception:
                        pass
                    # Circuit breaker: Spill to local disk WAL
                    return self.spool.spool_batch(chunk)

        return False

    def _try_drain_spool(self) -> None:
        """Attempts to drain pending WAL files if ClickHouse is reachable."""
        try:
            from backend.db.clickhouse_client import get_clickhouse_client
            client = get_clickhouse_client()
            drained = self.spool.drain_spool(client, max_files=5)
            if drained > 0:
                logger.info("Drained %d queued flows from disk spool WAL to ClickHouse", drained)
        except Exception:
            pass  # ClickHouse still offline; will retry on next cycle

    def flush(self) -> None:
        """Synchronously flushes any buffered flows immediately."""
        detached = self._swap_buffer()
        if detached:
            self._persist_chunk(detached)
        if self.spool.pending_count() > 0:
            self._try_drain_spool()

    def shutdown(self) -> None:
        """Gracefully flushes remaining flows and stops the worker thread."""
        self._running = False
        self._flush_trigger.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        self.flush()
        logger.info("ClickHouseDoubleBufferFlusher stopped cleanly.")


# Global singleton instance
clickhouse_flusher = ClickHouseDoubleBufferFlusher()
