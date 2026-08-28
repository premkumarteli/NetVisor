from __future__ import annotations

import logging
import queue
import time
from dataclasses import dataclass
from typing import Callable, Optional

logger = logging.getLogger("netvisor.packet_engine.ring_buffer")


@dataclass(slots=True)
class RawPacketEnvelope:
    raw_bytes: bytes
    timestamp: float
    priority: int = 2  # 0 = Control (High), 1 = Application (Medium), 2 = Bulk Data (Low)


class DualRingBuffer:
    """
    Thread-safe dual-queue ingestion buffer separating high-priority control traffic
    (SYN/FIN/RST/DNS/TLS/QUIC) from bulk data payloads to prevent queue starvation.
    """

    def __init__(self, control_capacity: int = 16384, data_capacity: int = 32768) -> None:
        self.control_queue: queue.Queue[RawPacketEnvelope] = queue.Queue(maxsize=control_capacity)
        self.data_queue: queue.Queue[RawPacketEnvelope] = queue.Queue(maxsize=data_capacity)
        self.control_capacity = control_capacity
        self.data_capacity = data_capacity

        # Operational Counters
        self.packets_received_total = 0
        self.packets_processed_total = 0
        self.control_drops_total = 0
        self.data_drops_total = 0
        self.capture_loop_exceptions_total = 0

    def push(self, raw_bytes: bytes, priority: int = 2, timestamp: float | None = None) -> bool:
        ts = timestamp if timestamp is not None else time.time()
        envelope = RawPacketEnvelope(raw_bytes=raw_bytes, timestamp=ts, priority=priority)
        self.packets_received_total += 1

        if priority == 0:
            # Control Traffic: Strict push. Drops packet only if Control Queue is 100% full.
            try:
                self.control_queue.put_nowait(envelope)
                return True
            except queue.Full:
                self.control_drops_total += 1
                logger.warning("Control Queue 100%% full! Dropping high-priority control frame.")
                return False
        else:
            # Application & Bulk Traffic: Push to Data Queue. Tail-drops oldest bulk data packet if full.
            try:
                self.data_queue.put_nowait(envelope)
                return True
            except queue.Full:
                self.data_drops_total += 1
                try:
                    # Tail-drop oldest data packet to make space
                    self.data_queue.get_nowait()
                    self.data_queue.put_nowait(envelope)
                    return True
                except (queue.Empty, queue.Full):
                    return False

    def pop_control_nowait(self) -> RawPacketEnvelope | None:
        try:
            item = self.control_queue.get_nowait()
            self.packets_processed_total += 1
            return item
        except queue.Empty:
            return None

    def pop_data_nowait(self) -> RawPacketEnvelope | None:
        try:
            item = self.data_queue.get_nowait()
            self.packets_processed_total += 1
            return item
        except queue.Empty:
            return None

    def peek_control_head(self) -> RawPacketEnvelope | None:
        with self.control_queue.mutex:
            if self.control_queue.queue:
                return self.control_queue.queue[0]
        return None

    def peek_data_head(self) -> RawPacketEnvelope | None:
        with self.data_queue.mutex:
            if self.data_queue.queue:
                return self.data_queue.queue[0]
        return None

    def control_depth_percent(self) -> float:
        if self.control_capacity <= 0:
            return 0.0
        return round((self.control_queue.qsize() / self.control_capacity) * 100.0, 2)

    def data_depth_percent(self) -> float:
        if self.data_capacity <= 0:
            return 0.0
        return round((self.data_queue.qsize() / self.data_capacity) * 100.0, 2)

    def get_health_metrics(self) -> dict:
        now = time.time()
        c_head = self.peek_control_head()
        d_head = self.peek_data_head()

        c_lag_ms = max(int((now - c_head.timestamp) * 1000), 0) if c_head else 0
        d_lag_ms = max(int((now - d_head.timestamp) * 1000), 0) if d_head else 0

        return {
            "control_queue_depth_percent": self.control_depth_percent(),
            "data_queue_depth_percent": self.data_depth_percent(),
            "control_queue_size": self.control_queue.qsize(),
            "data_queue_size": self.data_queue.qsize(),
            "control_queue_oldest_age_ms": c_lag_ms,
            "data_queue_oldest_age_ms": d_lag_ms,
            "packets_received_total": self.packets_received_total,
            "packets_processed_total": self.packets_processed_total,
            "packets_dropped_total": self.control_drops_total + self.data_drops_total,
            "control_queue_drops_total": self.control_drops_total,
            "data_queue_drops_total": self.data_drops_total,
            "capture_loop_exceptions_total": self.capture_loop_exceptions_total,
            "worker_lag_warning": c_lag_ms > 500 or d_lag_ms > 2000,
            "worker_lag_critical": c_lag_ms > 2000 or d_lag_ms > 5000,
        }


def wfq_worker_drain_loop(
    ring_buffer: DualRingBuffer,
    process_callback: Callable[[RawPacketEnvelope], None],
    stop_event: object,
    max_control_burst: int = 32,
    min_data_batch: int = 8,
) -> None:
    """
    Weighted Fair Queueing (WFQ) worker drain loop.
    Processes up to max_control_burst Control packets, then guarantees processing
    of min_data_batch Data packets to prevent queue starvation.
    """
    while not getattr(stop_event, "is_set", lambda: False)():
        control_processed = 0

        # Phase 1: Drain Control Queue up to max_control_burst
        while control_processed < max_control_burst:
            envelope = ring_buffer.pop_control_nowait()
            if envelope is None:
                break
            try:
                process_callback(envelope)
            except Exception as exc:
                ring_buffer.capture_loop_exceptions_total += 1
                logger.debug("Worker packet callback exception: %s", exc)
            control_processed += 1

        # Phase 2: Guaranteed processing of up to min_data_batch Data Queue packets
        data_processed = 0
        while data_processed < min_data_batch:
            envelope = ring_buffer.pop_data_nowait()
            if envelope is None:
                break
            try:
                process_callback(envelope)
            except Exception as exc:
                ring_buffer.capture_loop_exceptions_total += 1
                logger.debug("Worker packet callback exception: %s", exc)
            data_processed += 1

        # Idle sleep if both queues were empty
        if control_processed == 0 and data_processed == 0:
            time.sleep(0.001)
