import collections
import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

class DiskBackedBuffer:
    """A two-tier buffer for flow records: memory queue primary, SQLite WAL-mode overflow."""
    def __init__(self, db_path: Path, max_memory: int = 1000, max_disk_mb: int = 50):
        self.db_path = db_path
        self.max_memory = max_memory
        self.max_disk_mb = max_disk_mb
        
        self._memory_queue = collections.deque()
        self._lock = threading.RLock()
        
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            isolation_level=None  # Autocommit mode
        )
        self._conn.row_factory = sqlite3.Row
        self._init_db()
        
    def _init_db(self):
        with self._lock:
            # Enable WAL mode for better concurrency and performance
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS pending_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL DEFAULT (strftime('%s', 'now'))
                )
            """)
            
    def enqueue(self, record: dict) -> bool:
        """Put a record. Memory-first; if memory full, spill to SQLite."""
        with self._lock:
            if len(self._memory_queue) < self.max_memory:
                self._memory_queue.append(record)
                return True

            if self._conn is None:
                logger.error("Failed to enqueue record to disk buffer: buffer is closed")
                return False
                
            # Memory full, spill to disk
            payload_str = json.dumps(record)
            
            try:
                self._conn.execute(
                    "INSERT INTO pending_records (payload) VALUES (?)",
                    (payload_str,)
                )
                
                # Check DB size and evict if needed
                if self.disk_usage_bytes > self.max_disk_mb * 1024 * 1024:
                    self._evict_oldest_db_records()
                    
                return True
            except (AttributeError, sqlite3.Error) as e:
                logger.error(f"Failed to enqueue record to disk buffer: {e}")
                return False

    def _evict_oldest_db_records(self):
        """Evicts oldest rows if we're over the size limit. Assuming lock is held."""
        if self._conn is None:
            return
        try:
            self._conn.execute("""
                DELETE FROM pending_records 
                WHERE id IN (
                    SELECT id FROM pending_records 
                    ORDER BY id ASC LIMIT 1000
                )
            """)
            logger.warning(f"Disk buffer exceeded {self.max_disk_mb}MB limit. Evicted oldest records.")
        except sqlite3.Error as e:
            logger.error(f"Failed to evict from disk buffer: {e}")
            
    def drain(self, batch_size: int) -> list[dict]:
        """Pop up to batch_size records. Drain disk first (oldest), then memory."""
        results = []
        with self._lock:
            # 1. Drain from disk first (oldest)
            if self._conn is not None:
                try:
                    cursor = self._conn.execute(
                        "SELECT id, payload FROM pending_records ORDER BY id ASC LIMIT ?",
                        (batch_size,)
                    )
                    rows = cursor.fetchall()
                    if rows:
                        ids_to_delete = []
                        for row in rows:
                            try:
                                record = json.loads(row["payload"])
                                results.append(record)
                                ids_to_delete.append(str(row["id"]))
                            except json.JSONDecodeError:
                                logger.error(f"Failed to decode payload from disk buffer id={row['id']}")
                                ids_to_delete.append(str(row["id"]))
                                
                        if ids_to_delete:
                            placeholders = ",".join("?" * len(ids_to_delete))
                            self._conn.execute(
                                f"DELETE FROM pending_records WHERE id IN ({placeholders})",
                                ids_to_delete
                            )
                except sqlite3.Error as e:
                    logger.error(f"Failed to drain from disk buffer: {e}")
                
            # 2. Fill the rest of the batch from memory
            remaining = batch_size - len(results)
            while remaining > 0 and self._memory_queue:
                results.append(self._memory_queue.popleft())
                remaining -= 1
                
        return results

    @property
    def disk_usage_bytes(self) -> int:
        """Current SQLite file size in bytes when disk-backed records exist."""
        if self.disk_pending_count <= 0:
            return 0
        total = 0
        for path in (self.db_path, self.db_path.with_suffix(self.db_path.suffix + "-wal")):
            if path.exists():
                total += path.stat().st_size
        return total

    @property
    def disk_pending_count(self) -> int:
        """Total records currently stored on disk."""
        with self._lock:
            return self._disk_pending_count_unlocked()

    def _disk_pending_count_unlocked(self) -> int:
        if self._conn is None:
            return 0
        try:
            cursor = self._conn.execute("SELECT COUNT(*) FROM pending_records")
            row = cursor.fetchone()
            return int(row[0] if row else 0)
        except sqlite3.Error:
            return 0

    @property
    def memory_pending_count(self) -> int:
        """Total records currently stored in memory."""
        with self._lock:
            return len(self._memory_queue)

    def requeue_front(self, records: list[dict[str, Any]]) -> None:
        """Return drained records to the front of the in-memory queue in original order."""
        if not records:
            return
        with self._lock:
            for record in reversed(records):
                self._memory_queue.appendleft(record)

    @property
    def pending_count(self) -> int:
        """Total records across memory + disk."""
        with self._lock:
            mem_count = len(self._memory_queue)
            disk_count = self._disk_pending_count_unlocked()
            return mem_count + disk_count

    def close(self):
        """Flush and close SQLite connection."""
        with self._lock:
            if self._conn:
                try:
                    self._conn.close()
                except Exception as e:
                    logger.error(f"Error closing DB connection: {e}")
                self._conn = None
