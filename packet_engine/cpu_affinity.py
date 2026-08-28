from __future__ import annotations

import os
import sys
import ctypes
import logging
import threading
from typing import List, Optional

logger = logging.getLogger("netvisor.packet_engine.cpu_affinity")


class CPUAffinityManager:
    """
    Multi-Core Worker Thread-Level CPU Affinity & NUMA Core Binding Manager.
    Pins specific worker threads (Capture Thread -> CPU0, Workers -> CPU1..N) to physical CPU cores
    to eliminate cross-CPU L1/L2 cache line thrashing.
    """

    __slots__ = ("_num_cpus",)

    def __init__(self) -> None:
        self._num_cpus = os.cpu_count() or 1

    def pin_current_thread_to_core(self, core_id: int) -> bool:
        """Pins the calling THREAD specifically (not just process) to a target CPU core ID."""
        target_core = core_id % self._num_cpus

        # 1. Linux pthread_setaffinity_np
        if hasattr(os, "sched_setaffinity"):
            try:
                # 0 target means current calling thread on Linux
                os.sched_setaffinity(0, {target_core})
                logger.info(f"Thread '{threading.current_thread().name}' pinned to Linux CPU core {target_core}")
                return True
            except Exception as e:
                logger.debug(f"Linux sched_setaffinity failed: {e}")

        # 2. Windows SetThreadAffinityMask via ctypes
        if sys.platform == "win32":
            try:
                kernel32 = ctypes.windll.kernel32
                thread_handle = kernel32.GetCurrentThread()
                mask = 1 << target_core
                result = kernel32.SetThreadAffinityMask(thread_handle, ctypes.c_size_t(mask))
                if result != 0:
                    logger.info(f"Thread '{threading.current_thread().name}' pinned to Windows CPU core {target_core}")
                    return True
            except Exception as e:
                logger.debug(f"Windows SetThreadAffinityMask failed: {e}")

        # 3. Fallback via psutil
        try:
            import psutil
            proc = psutil.Process()
            proc.cpu_affinity([target_core])
            logger.info(f"Thread '{threading.current_thread().name}' pinned via psutil fallback to CPU core {target_core}")
            return True
        except Exception as e:
            logger.debug(f"CPU core affinity binding to core {target_core} skipped: {e}")
            return False

    def pin_capture_thread(self) -> bool:
        """Helper to pin capture thread to CPU 0."""
        return self.pin_current_thread_to_core(0)

    def pin_worker_thread(self, worker_index: int) -> bool:
        """Helper to pin worker thread N to CPU (N+1)."""
        return self.pin_current_thread_to_core(worker_index + 1)

    def get_core_assignment_for_shard(self, shard_index: int, total_shards: int = 16) -> int:
        """Maps a flow manager shard index to a physical CPU core ID."""
        return (shard_index + 1) % self._num_cpus
