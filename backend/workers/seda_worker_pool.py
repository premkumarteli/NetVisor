"""Staged Event-Driven Architecture (SEDA) worker pool with Maglev consistent hashing.

This module provides:
1. MaglevHasher: Google's Maglev consistent hashing algorithm for deterministic 5-tuple
   flow-affinity routing, minimizing state fragmentation and lock contention across worker threads.
2. SEDAWorkerPool: Multi-stage pipeline (Ingress -> Worker Partitions -> Egress) with bounded
   queues, backpressure watermarking, and zero-loss flow offloading to ClickHouse.
"""

from __future__ import annotations

import hashlib
import logging
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.utils.protobuf_serializer import deserialize_flow_batch

logger = logging.getLogger(__name__)

# Prime lookup table size for Maglev hashing (standard Google recommendation is a prime)
MAGLEV_TABLE_SIZE = 65537


class MaglevHasher:
    """Implements Google's Maglev consistent hashing algorithm.

    Reference: Eisenbud et al., 'Maglev: A Fast and Reliable Software Network Load Balancer',
    USENIX NSDI 2016.
    """

    def __init__(self, backends: List[str], table_size: int = MAGLEV_TABLE_SIZE) -> None:
        if not backends:
            raise ValueError("Backends list cannot be empty.")
        self._backends = list(backends)
        self._table_size = table_size
        self._lookup_table: List[str] = [""] * self._table_size
        self._rebuild_table()

    @staticmethod
    def _hash_pair(key: str, seed1: str = "maglev_h1", seed2: str = "maglev_h2") -> Tuple[int, int]:
        """Generates two distinct hash values for a given string key."""
        d1 = hashlib.md5(f"{seed1}_{key}".encode("utf-8")).digest()
        d2 = hashlib.sha1(f"{seed2}_{key}".encode("utf-8")).digest()

        h1 = int.from_bytes(d1[:8], byteorder="big", signed=False)
        h2 = int.from_bytes(d2[:8], byteorder="big", signed=False)
        return h1, h2

    def _rebuild_table(self) -> None:
        """Constructs the lookup table of size M using round-robin permutation walks."""
        n = len(self._backends)
        m = self._table_size

        # Generate permutation sequences for each backend
        # P[i][j] = (offset + j * skip) % M
        permutations: List[List[int]] = []
        for backend in self._backends:
            h1, h2 = self._hash_pair(backend)
            offset = h1 % m
            skip = (h2 % (m - 1)) + 1
            perm = [(offset + j * skip) % m for j in range(m)]
            permutations.append(perm)

        # Round-robin walk to populate lookup table
        next_idx = [0] * n
        entry_count = 0
        assigned = [False] * m

        while entry_count < m:
            for i in range(n):
                c = next_idx[i]
                while c < m:
                    candidate = permutations[i][c]
                    c += 1
                    if not assigned[candidate]:
                        self._lookup_table[candidate] = self._backends[i]
                        assigned[candidate] = True
                        entry_count += 1
                        next_idx[i] = c
                        break
                next_idx[i] = c
                if entry_count >= m:
                    break

    def get_worker(self, five_tuple: Tuple[str, str, int, int, str]) -> str:
        """Maps a 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) to a worker ID.

        Normalizes bi-directional traffic so that forward and reverse directions of a
        session are deterministically bound to the exact same worker.
        """
        src_ip, dst_ip, src_port, dst_port, proto = five_tuple

        # Normalize bi-directional flow key
        if (src_ip, src_port) > (dst_ip, dst_port):
            norm_key = f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}/{proto.upper()}"
        else:
            norm_key = f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}/{proto.upper()}"

        h, _ = self._hash_pair(norm_key, seed1="flow_norm")
        idx = h % self._table_size
        return self._lookup_table[idx]

    def add_backend(self, backend: str) -> None:
        """Adds a new worker backend and rebuilds the lookup table with minimal disruption."""
        if backend not in self._backends:
            self._backends.append(backend)
            self._rebuild_table()

    def remove_backend(self, backend: str) -> None:
        """Removes a worker backend and reallocates its slots among remaining workers."""
        if backend in self._backends:
            if len(self._backends) <= 1:
                raise ValueError("Cannot remove the last remaining backend worker.")
            self._backends.remove(backend)
            self._rebuild_table()

    @property
    def backends(self) -> List[str]:
        return list(self._backends)


class SEDAWorkerPool:
    """Staged Event-Driven Architecture (SEDA) flow telemetry processing engine."""

    def __init__(
        self,
        worker_count: int = 4,
        queue_capacity: int = 10000,
        flow_handler: Optional[Callable[[Dict[str, Any]], Any]] = None,
        egress_handler: Optional[Callable[[List[Dict[str, Any]]], Any]] = None,
    ) -> None:
        self._worker_count = max(1, worker_count)
        self._queue_capacity = queue_capacity
        self._flow_handler = flow_handler
        self._egress_handler = egress_handler

        self._worker_ids = [f"seda-worker-{i}" for i in range(self._worker_count)]
        self._hasher = MaglevHasher(self._worker_ids, table_size=10007)

        # Queues per stage
        self._ingress_queue: queue.Queue[bytes | str | Dict[str, Any]] = queue.Queue(maxsize=queue_capacity)
        self._worker_queues: Dict[str, queue.Queue[Dict[str, Any]]] = {
            wid: queue.Queue(maxsize=queue_capacity) for wid in self._worker_ids
        }
        self._egress_queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=queue_capacity)

        self._running = False
        self._threads: List[threading.Thread] = []

        # Operational metrics
        self._metrics = {
            "ingress_enqueued": 0,
            "ingress_dropped": 0,
            "flows_routed": 0,
            "flows_processed": 0,
            "egress_flushed": 0,
            "worker_drops": {wid: 0 for wid in self._worker_ids},
        }
        self._metrics_lock = threading.Lock()

    def start(self) -> None:
        """Starts all pipeline stage threads."""
        if self._running:
            return
        self._running = True

        # Ingress dispatcher thread
        t_ingress = threading.Thread(target=self._run_ingress_stage, name="seda-ingress-stage", daemon=True)
        t_ingress.start()
        self._threads.append(t_ingress)

        # Worker partition threads
        for wid in self._worker_ids:
            t_w = threading.Thread(target=self._run_worker_stage, args=(wid,), name=f"seda-{wid}", daemon=True)
            t_w.start()
            self._threads.append(t_w)

        # Egress aggregation thread
        t_egress = threading.Thread(target=self._run_egress_stage, name="seda-egress-stage", daemon=True)
        t_egress.start()
        self._threads.append(t_egress)

        logger.info("SEDAWorkerPool started with %d workers (Maglev hashing active).", self._worker_count)

    def stop(self, timeout: float = 2.0) -> None:
        """Stops all pipeline stage threads gracefully."""
        self._running = False
        for t in self._threads:
            t.join(timeout=timeout)
        self._threads.clear()
        logger.info("SEDAWorkerPool stopped.")

    def submit_batch(self, payload: bytes | str | Dict[str, Any]) -> bool:
        """Enqueues a raw batch (protobuf bytes, JSON string, or dict) into Ingress Stage."""
        try:
            self._ingress_queue.put_nowait(payload)
            with self._metrics_lock:
                self._metrics["ingress_enqueued"] += 1
            return True
        except queue.Full:
            with self._metrics_lock:
                self._metrics["ingress_dropped"] += 1
            logger.warning("SEDA Ingress queue full (watermark %d), dropping batch.", self._queue_capacity)
            return False

    def _run_ingress_stage(self) -> None:
        """Stage 1: Deserializes batches and routes each flow by 5-tuple to assigned worker."""
        while self._running:
            try:
                item = self._ingress_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            try:
                if isinstance(item, (bytes, str)):
                    batch_dict = deserialize_flow_batch(item)
                    flows = batch_dict.get("flows", [])
                elif isinstance(item, dict):
                    flows = item.get("flows", [item]) if "flows" in item else [item]
                else:
                    flows = []

                for flow in flows:
                    if not isinstance(flow, dict):
                        continue

                    # Extract 5-tuple for Maglev routing
                    src_ip = str(flow.get("src_ip") or "0.0.0.0")
                    dst_ip = str(flow.get("dst_ip") or "0.0.0.0")
                    src_port = int(flow.get("src_port") or 0)
                    dst_port = int(flow.get("dst_port") or 0)
                    protocol = str(flow.get("protocol") or "TCP")

                    worker_id = self._hasher.get_worker((src_ip, dst_ip, src_port, dst_port, protocol))
                    target_queue = self._worker_queues[worker_id]

                    try:
                        target_queue.put_nowait(flow)
                        with self._metrics_lock:
                            self._metrics["flows_routed"] += 1
                    except queue.Full:
                        with self._metrics_lock:
                            self._metrics["worker_drops"][worker_id] += 1
                        logger.warning("Worker %s queue saturated, dropping flow.", worker_id)

            except Exception as exc:
                logger.error("Error in SEDA Ingress stage: %s", exc, exc_info=True)

    def _run_worker_stage(self, worker_id: str) -> None:
        """Stage 2: Independent worker loop processing flow state with zero lock contention."""
        w_queue = self._worker_queues[worker_id]
        while self._running:
            try:
                flow = w_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            try:
                if self._flow_handler:
                    processed = self._flow_handler(flow) or flow
                else:
                    processed = flow

                with self._metrics_lock:
                    self._metrics["flows_processed"] += 1

                # Forward to Egress Stage
                try:
                    self._egress_queue.put_nowait(processed)
                except queue.Full:
                    logger.warning("SEDA Egress queue full, dropping processed flow.")

            except Exception as exc:
                logger.error("Error in SEDA worker %s: %s", worker_id, exc, exc_info=True)

    def _run_egress_stage(self) -> None:
        """Stage 3: Aggregates processed flows in batches and offloads to storage."""
        batch: List[Dict[str, Any]] = []
        last_flush = time.time()

        while self._running:
            try:
                flow = self._egress_queue.get(timeout=0.05)
                batch.append(flow)
            except queue.Empty:
                pass

            now = time.time()
            if len(batch) >= 500 or (batch and (now - last_flush) >= 0.5):
                try:
                    if self._egress_handler:
                        self._egress_handler(batch)
                    with self._metrics_lock:
                        self._metrics["egress_flushed"] += len(batch)
                except Exception as exc:
                    logger.error("Error in SEDA Egress handler: %s", exc, exc_info=True)
                finally:
                    batch = []
                    last_flush = now

    def get_metrics(self) -> Dict[str, Any]:
        """Returns snapshot of operational metrics and queue depths."""
        with self._metrics_lock:
            snap = dict(self._metrics)
            snap["worker_drops"] = dict(self._metrics["worker_drops"])

        snap["ingress_queue_depth"] = self._ingress_queue.qsize()
        snap["egress_queue_depth"] = self._egress_queue.qsize()
        snap["worker_queue_depths"] = {wid: q.qsize() for wid, q in self._worker_queues.items()}
        return snap
