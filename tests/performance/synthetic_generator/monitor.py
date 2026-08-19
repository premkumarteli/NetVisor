import time
import psutil
import logging
from backend.db.session import get_db_connection

logger = logging.getLogger("netvisor.replay.monitor")

class ResourceMonitor:
    """Periodically records target server CPU, memory, and database queue depths."""
    
    def __init__(self, server_pid: int):
        self.server_pid = server_pid
        self.history = []
        self.proc_cache = {}
        
        try:
            self.proc = psutil.Process(server_pid)
            self.proc_cache[server_pid] = self.proc
            # Initialize CPU percent counters to establish a baseline
            self.proc.cpu_percent(interval=None)
        except Exception:
            self.proc = None

    def sample(self):
        timestamp = time.time()
        cpu_pct = 0.0
        ram_mb = 0.0
        queue_depth = 0
        
        # 1. Gather Process Resource Stats recursively across process tree
        if self.proc:
            try:
                # Find all active descendant processes
                current_pids = {self.server_pid}
                try:
                    children = self.proc.children(recursive=True)
                    for child in children:
                        current_pids.add(child.pid)
                except Exception:
                    children = []
                
                # Evict dead PIDs from cache
                self.proc_cache = {pid: proc for pid, proc in self.proc_cache.items() if pid in current_pids}
                
                # Populate new PIDs into cache
                for child in children:
                    if child.pid not in self.proc_cache:
                        try:
                            child.cpu_percent(interval=None)
                            self.proc_cache[child.pid] = child
                        except Exception:
                            pass
                
                total_cpu = 0.0
                total_ram_bytes = 0
                
                for pid, p in self.proc_cache.items():
                    try:
                        total_cpu += p.cpu_percent(interval=None)
                        total_ram_bytes += p.memory_info().rss
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                cpu_pct = total_cpu
                ram_mb = total_ram_bytes / (1024 * 1024)
            except Exception as e:
                logger.warning(f"Error sampling process resources: {e}")
                
        # 2. Gather DB Ingestion Queue Depth
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM flow_ingest_batches WHERE status = 'pending'")
            row = cursor.fetchone()
            if row:
                queue_depth = row[0]
            conn.close()
        except Exception as e:
            logger.warning(f"Error sampling queue depth: {e}")
            
        self.history.append({
            "timestamp": timestamp,
            "cpu_pct": cpu_pct,
            "ram_mb": ram_mb,
            "queue_depth": queue_depth
        })
