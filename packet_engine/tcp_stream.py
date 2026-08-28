from __future__ import annotations

import heapq
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("netvisor.packet_engine.tcp_stream")


class TCPStreamStateEnum(Enum):
    LISTEN = auto()
    SYN_SENT = auto()
    SYN_RECEIVED = auto()
    ESTABLISHED = auto()
    FIN_WAIT = auto()
    CLOSED = auto()
    RESET = auto()


def seq_lt(a: int, b: int) -> bool:
    """RFC 793 32-bit modular sequence comparison: returns True if a < b."""
    return ((a - b) & 0xFFFFFFFF) > 0x80000000


def seq_lte(a: int, b: int) -> bool:
    return a == b or seq_lt(a, b)


def seq_gt(a: int, b: int) -> bool:
    return seq_lt(b, a)


def seq_gte(a: int, b: int) -> bool:
    return a == b or seq_gt(a, b)


@dataclass(slots=True)
class TCPSegment:
    seq: int
    ack: int
    payload: bytes
    flags: str
    timestamp: float


class TCPStreamBuffer:
    """
    Per-flow TCP Stream Reassembly Buffer.
    Tracks TCP 32-bit modular sequence numbers, handles overlapping segments,
    buffers out-of-order segments in a min-heap, and enforces per-stream memory caps (default 512KB).
    """

    def __init__(
        self,
        flow_key: tuple,
        max_stream_bytes: int = 512 * 1024,
        max_idle_seconds: float = 60.0,
        max_stream_age_seconds: float = 300.0,
    ) -> None:
        self.flow_key = flow_key
        self.max_stream_bytes = max_stream_bytes
        self.max_idle_seconds = max_idle_seconds
        self.max_stream_age_seconds = max_stream_age_seconds

        self.state: TCPStreamStateEnum = TCPStreamStateEnum.LISTEN
        self.created_at: float = time.time()
        self.last_seen: float = time.time()

        self.next_expected_seq: int = 0
        self.retransmissions_count: int = 0
        self.out_of_order_count: int = 0
        self.total_assembled_bytes: int = 0

        # Min-heap storing out-of-order segments: (seq_number, payload_bytes)
        self.out_of_order_heap: List[Tuple[int, bytes]] = []
        self.in_order_stream: bytearray = bytearray()
        self._buffered_bytes: int = 0

    @property
    def memory_footprint_bytes(self) -> int:
        return self._buffered_bytes

    def is_expired(self, now: float | None = None) -> bool:
        ts = now if now is not None else time.time()
        if ts - self.last_seen >= self.max_idle_seconds:
            return True
        if ts - self.created_at >= self.max_stream_age_seconds:
            return True
        return False

    def process_segment(self, seq: int, ack: int, payload: bytes, flags: str, timestamp: float | None = None) -> bytes:
        now = timestamp if timestamp is not None else time.time()
        self.last_seen = now

        # Update TCP Stream State Machine
        if "S" in flags and "A" not in flags:
            self.state = TCPStreamStateEnum.SYN_SENT
            self.next_expected_seq = (seq + 1) & 0xFFFFFFFF
            return b""
        elif "S" in flags and "A" in flags:
            self.state = TCPStreamStateEnum.SYN_RECEIVED
            self.next_expected_seq = (seq + 1) & 0xFFFFFFFF
            return b""
        elif "R" in flags:
            self.state = TCPStreamStateEnum.RESET
            return b""
        elif "F" in flags:
            if self.state != TCPStreamStateEnum.CLOSED:
                self.state = TCPStreamStateEnum.FIN_WAIT

        if self.state in (TCPStreamStateEnum.SYN_SENT, TCPStreamStateEnum.SYN_RECEIVED):
            self.state = TCPStreamStateEnum.ESTABLISHED

        if not payload:
            return b""

        # Calculate modular payload end sequence
        end_seq = (seq + len(payload)) & 0xFFFFFFFF

        # Retransmission & Overlap Detection using modular sequence arithmetic
        if self.next_expected_seq > 0 and seq_lte(end_seq, self.next_expected_seq):
            self.retransmissions_count += 1
            return b""  # Pure retransmission: ignore

        # Overlapping Segment Handling: Trim leading bytes already received
        if self.next_expected_seq > 0 and seq_lt(seq, self.next_expected_seq) and seq_gt(end_seq, self.next_expected_seq):
            overlap = (self.next_expected_seq - seq) & 0xFFFFFFFF
            payload = payload[overlap:]
            seq = self.next_expected_seq
            self.retransmissions_count += 1

        # Enforce Per-Stream Memory Cap (512KB default limit)
        if self._buffered_bytes + len(payload) > self.max_stream_bytes:
            logger.debug("Stream %s reached per-flow 512KB cap. Dropping payload segment.", self.flow_key)
            return b""

        # In-Order Segment Processing
        if seq == self.next_expected_seq or self.next_expected_seq == 0:
            self.next_expected_seq = (seq + len(payload)) & 0xFFFFFFFF
            self.in_order_stream.extend(payload)
            self._buffered_bytes += len(payload)
            self.total_assembled_bytes += len(payload)

            # Drain contiguous out-of-order heap entries
            while self.out_of_order_heap and seq_lte(self.out_of_order_heap[0][0], self.next_expected_seq):
                buffered_seq, buffered_payload = heapq.heappop(self.out_of_order_heap)
                self._buffered_bytes -= len(buffered_payload)
                buffered_end = (buffered_seq + len(buffered_payload)) & 0xFFFFFFFF

                if seq_gt(buffered_end, self.next_expected_seq):
                    overlap = (self.next_expected_seq - buffered_seq) & 0xFFFFFFFF
                    valid_chunk = buffered_payload[overlap:]
                    self.next_expected_seq = (self.next_expected_seq + len(valid_chunk)) & 0xFFFFFFFF
                    self.in_order_stream.extend(valid_chunk)
                    self._buffered_bytes += len(valid_chunk)
                    self.total_assembled_bytes += len(valid_chunk)

        elif seq_gt(seq, self.next_expected_seq):
            # Out-of-order segment -> Buffer in min-heap
            heapq.heappush(self.out_of_order_heap, (seq, payload))
            self._buffered_bytes += len(payload)
            self.out_of_order_count += 1

        flushed = bytes(self.in_order_stream)
        self._buffered_bytes -= len(self.in_order_stream)
        self.in_order_stream.clear()
        return flushed


class TCPStreamTrackerManager:
    """
    16-Shard Lock-Partitioned TCP Stream Tracker Manager.
    Features 16 lock shards, O(1) incremental memory accounting, immediate post-processing
    global memory budget enforcement (512MB default), and modular 32-bit TCP sequence tracking.
    """
    NUM_SHARDS = 16

    def __init__(
        self,
        max_global_memory_bytes: int = 512 * 1024 * 1024,  # 512 MB Global Cap
        max_stream_bytes: int = 512 * 1024,                # 512 KB Per-Flow Cap
        max_idle_seconds: float = 60.0,
        max_stream_age_seconds: float = 300.0,
    ) -> None:
        self.max_global_memory_bytes = max_global_memory_bytes
        self.max_stream_bytes = max_stream_bytes
        self.max_idle_seconds = max_idle_seconds
        self.max_stream_age_seconds = max_stream_age_seconds

        # 16 Sharded Dictionaries & Locks
        self._shards: List[Dict[tuple, TCPStreamBuffer]] = [{} for _ in range(self.NUM_SHARDS)]
        self._locks: List[threading.Lock] = [threading.Lock() for _ in range(self.NUM_SHARDS)]

        # O(1) Incremental Memory Counters per Shard
        self._shard_memory_bytes: List[int] = [0 for _ in range(self.NUM_SHARDS)]

        # Global Telemetry Counters
        self.streams_tracked_total = 0
        self.retransmissions_detected_total = 0
        self.out_of_order_buffered_total = 0
        self.stream_bytes_assembled_total = 0

    def _get_shard_index(self, flow_key: tuple) -> int:
        return abs(hash(flow_key)) % self.NUM_SHARDS

    def current_global_memory_bytes(self) -> int:
        """O(1) Memory Aggregation across 16 shards."""
        return sum(self._shard_memory_bytes)

    def _enforce_global_memory_budget_locked(self, shard_idx: int, now: float) -> None:
        """Enforces stream age pruning and global 512MB memory budget immediately."""
        shard = self._shards[shard_idx]
        
        # 1. Prune expired / idle streams
        expired_keys = [k for k, s in shard.items() if s.is_expired(now)]
        for k in expired_keys:
            st = shard.pop(k, None)
            if st:
                self._shard_memory_bytes[shard_idx] -= st.memory_footprint_bytes

        # 2. If total memory across shards exceeds cap, evict oldest streams in this shard
        if self.current_global_memory_bytes() > self.max_global_memory_bytes and shard:
            logger.warning(
                "Global TCP Stream memory (%d MB) exceeds cap (%d MB). Evicting oldest streams in shard %d.",
                self.current_global_memory_bytes() // (1024 * 1024),
                self.max_global_memory_bytes // (1024 * 1024),
                shard_idx,
            )
            sorted_streams = sorted(shard.items(), key=lambda kv: kv[1].last_seen)
            for k, st in sorted_streams:
                shard.pop(k, None)
                self._shard_memory_bytes[shard_idx] -= st.memory_footprint_bytes
                if self.current_global_memory_bytes() <= self.max_global_memory_bytes:
                    break

    def process_packet_segment(
        self, flow_key: tuple, seq: int, ack: int, payload: bytes, flags: str, timestamp: float | None = None
    ) -> bytes:
        now = timestamp if timestamp is not None else time.time()
        shard_idx = self._get_shard_index(flow_key)

        with self._locks[shard_idx]:
            shard = self._shards[shard_idx]
            stream = shard.get(flow_key)

            if stream is None:
                stream = TCPStreamBuffer(
                    flow_key=flow_key,
                    max_stream_bytes=self.max_stream_bytes,
                    max_idle_seconds=self.max_idle_seconds,
                    max_stream_age_seconds=self.max_stream_age_seconds,
                )
                shard[flow_key] = stream
                self.streams_tracked_total += 1

            # Track deltas before processing to avoid double-counting bug
            prev_retrans = stream.retransmissions_count
            prev_ooo = stream.out_of_order_count
            prev_mem = stream.memory_footprint_bytes

            flushed_bytes = stream.process_segment(seq, ack, payload, flags, now)

            # Update delta metrics accurately
            delta_retrans = stream.retransmissions_count - prev_retrans
            delta_ooo = stream.out_of_order_count - prev_ooo
            delta_mem = stream.memory_footprint_bytes - prev_mem

            self.retransmissions_detected_total += delta_retrans
            self.out_of_order_buffered_total += delta_ooo
            self.stream_bytes_assembled_total += len(flushed_bytes)
            self._shard_memory_bytes[shard_idx] += delta_mem

            # Enforce memory budget AFTER payload processing completes
            self._enforce_global_memory_budget_locked(shard_idx, now)

            if stream.state in (TCPStreamStateEnum.CLOSED, TCPStreamStateEnum.RESET):
                st = shard.pop(flow_key, None)
                if st:
                    self._shard_memory_bytes[shard_idx] -= st.memory_footprint_bytes

            return flushed_bytes

    def status_snapshot(self) -> dict:
        active_streams = 0
        for i in range(self.NUM_SHARDS):
            with self._locks[i]:
                active_streams += len(self._shards[i])
        global_mem = self.current_global_memory_bytes()

        return {
            "active_tcp_streams_count": active_streams,
            "num_shards": self.NUM_SHARDS,
            "global_memory_bytes": global_mem,
            "global_memory_mb": round(global_mem / (1024 * 1024), 2),
            "max_global_memory_mb": round(self.max_global_memory_bytes / (1024 * 1024), 2),
            "streams_tracked_total": self.streams_tracked_total,
            "retransmissions_detected_total": self.retransmissions_detected_total,
            "out_of_order_buffered_total": self.out_of_order_buffered_total,
            "stream_bytes_assembled_total": self.stream_bytes_assembled_total,
        }
