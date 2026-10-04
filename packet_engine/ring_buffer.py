from __future__ import annotations

import logging
import queue
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

logger = logging.getLogger("netvisor.packet_engine.ring_buffer")


class SourceIpTokenBucket:
    """
    Token Bucket Rate Limiter per Source IP for Priority 0 Control Path Admission.
    Guarantees legitimate control traffic (SYN, DNS, TLS) admission during single-source
    or multi-source volumetric control floods by diverting excess to the bulk data queue.
    """

    def __init__(self, rate: float = 20.0, burst: float = 50.0, max_tracked_ips: int = 10000) -> None:
        self.rate = float(rate)
        self.burst = float(burst)
        self.max_tracked_ips = max_tracked_ips
        self._buckets: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_ts)
        self._lock = threading.Lock()

    def consume(self, src_ip: str, tokens: float = 1.0, timestamp: float | None = None) -> bool:
        now = timestamp if timestamp is not None else time.time()
        with self._lock:
            if src_ip in self._buckets:
                curr_tokens, last_ts = self._buckets[src_ip]
                elapsed = max(0.0, now - last_ts)
                curr_tokens = min(self.burst, curr_tokens + elapsed * self.rate)
            else:
                if len(self._buckets) >= self.max_tracked_ips:
                    oldest_ip = min(self._buckets.keys(), key=lambda k: self._buckets[k][1])
                    self._buckets.pop(oldest_ip, None)
                curr_tokens = self.burst

            if curr_tokens >= tokens:
                curr_tokens -= tokens
                self._buckets[src_ip] = (curr_tokens, now)
                return True
            else:
                self._buckets[src_ip] = (curr_tokens, now)
                return False

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


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

    def __init__(
        self,
        control_capacity: int = 16384,
        data_capacity: int = 32768,
        token_rate: float = 20.0,
        token_burst: float = 50.0,
    ) -> None:
        self.control_queue: queue.Queue[RawPacketEnvelope] = queue.Queue(maxsize=control_capacity)
        self.data_queue: queue.Queue[RawPacketEnvelope] = queue.Queue(maxsize=data_capacity)
        self.control_capacity = control_capacity
        self.data_capacity = data_capacity
        self.token_bucket = SourceIpTokenBucket(rate=token_rate, burst=token_burst)

        # Thread-safe counter lock (separate from queue mutexes)
        self._counter_lock = threading.Lock()

        # Operational Counters
        self.packets_received_total = 0
        self.packets_processed_total = 0
        self.control_drops_total = 0
        self.data_drops_total = 0
        self.control_rate_limited_total = 0
        self.capture_loop_exceptions_total = 0

    def _increment_counter(self, name: str, amount: int = 1) -> None:
        """Thread-safe counter increment."""
        with self._counter_lock:
            setattr(self, name, getattr(self, name) + amount)

    @staticmethod
    def _extract_src_ip_fast(raw_bytes: bytes) -> str | None:
        """Zero-overhead extraction of src IP for rate limiting from Ethernet or raw IP frames."""
        length = len(raw_bytes)
        if length < 20:
            return None
        try:
            # Ethernet IPv4 (offset 12-13 == 0x0800, src IP at 26..30)
            if length >= 34 and raw_bytes[12] == 0x08 and raw_bytes[13] == 0x00:
                return socket.inet_ntoa(raw_bytes[26:30])
            # Direct raw IPv4 (first nibble == 4, src IP at 12..16)
            if (raw_bytes[0] >> 4) == 4 and length >= 20:
                return socket.inet_ntoa(raw_bytes[12:16])
            # Direct raw IPv6 (first nibble == 6, src IP at 8..24)
            if (raw_bytes[0] >> 4) == 6 and length >= 40:
                return socket.inet_ntop(socket.AF_INET6, raw_bytes[8:24])
            # Ethernet IPv6 (offset 12-13 == 0x86DD, src IP at 22..38)
            if length >= 54 and raw_bytes[12] == 0x86 and raw_bytes[13] == 0xDD:
                return socket.inet_ntop(socket.AF_INET6, raw_bytes[22:38])
        except Exception:
            pass
        return None

    def push(
        self,
        raw_bytes: bytes,
        priority: int = 2,
        timestamp: float | None = None,
        src_ip: str | None = None,
    ) -> bool:
        ts = timestamp if timestamp is not None else time.time()
        self._increment_counter("packets_received_total")

        # Per-source-IP token bucket admission check for Priority 0 (Control)
        if priority == 0:
            if src_ip is None:
                src_ip = self._extract_src_ip_fast(raw_bytes)

            admitted = True
            if src_ip:
                admitted = self.token_bucket.consume(src_ip, timestamp=ts)

            if not admitted:
                # Excess control packets are downgraded to bulk data queue and counted
                self._increment_counter("control_rate_limited_total")
                priority = 2

        envelope = RawPacketEnvelope(raw_bytes=raw_bytes, timestamp=ts, priority=priority)

        if priority == 0:
            # Control Traffic: Strict push. Drops packet only if Control Queue is 100% full.
            try:
                self.control_queue.put_nowait(envelope)
                return True
            except queue.Full:
                self._increment_counter("control_drops_total")
                logger.warning("Control Queue 100%% full! Dropping high-priority control frame.")
                return False
        else:
            # Application & Bulk Traffic: Push to Data Queue. Tail-drops oldest bulk data packet if full.
            try:
                self.data_queue.put_nowait(envelope)
                return True
            except queue.Full:
                self._increment_counter("data_drops_total")
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
            self._increment_counter("packets_processed_total")
            return item
        except queue.Empty:
            return None

    def pop_data_nowait(self) -> RawPacketEnvelope | None:
        try:
            item = self.data_queue.get_nowait()
            self._increment_counter("packets_processed_total")
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
            "control_rate_limited_total": self.control_rate_limited_total,
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
