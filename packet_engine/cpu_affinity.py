from __future__ import annotations

import os
import sys
import logging
from typing import List, Optional

logger = logging.getLogger("netvisor.packet_engine.cpu_affinity")


class CPUAffinityManager:
    """
    Multi-Core Worker CPU Affinity & NUMA Core Binding Manager.
    Pins packet processing worker threads and 16-shard flow buckets to specific CPU cores
    to eliminate cross-CPU L1/L2 cache line thrashing.
    """

    __slots__ = ("_num_cpus",)

    def __init__(self) -> None:
        self._num_cpus = os.cpu_count() or 1

    def pin_current_thread_to_core(self, core_id: int) -> bool:
        """Pins the calling thread/process to a target CPU core ID."""
        target_core = core_id % self._num_cpus
        try:
            if hasattr(os, "sched_setaffinity"):
                # Linux affinity
                os.sched_setaffinity(0, {target_core})
                logger.info(f"Successfully pinned thread to Linux CPU core {target_core}")
                return True
            else:
                # Windows affinity via psutil if available
                import psutil
                proc = psutil.Process()
                proc.cpu_affinity([target_core])
                logger.info(f"Successfully pinned thread to Windows CPU core {target_core}")
                return True
        except Exception as e:
            logger.debug(f"CPU core affinity binding to core {target_core} skipped: {e}")
            return False

    def get_core_assignment_for_shard(self, shard_index: int, total_shards: int = 16) -> int:
        """Maps a flow manager shard index to a physical CPU core ID."""
        return shard_index % self._num_cpus
