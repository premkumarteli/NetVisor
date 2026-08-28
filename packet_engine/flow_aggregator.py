from __future__ import annotations

import threading
import time
import heapq
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, Optional, Tuple

from .parser import PacketObservation


FlowKey = (
    Tuple[Tuple[str, str], Tuple[int, int], str, Tuple[str, str], str, int]
    | Tuple[str, str, int, int, str]
)
GENERIC_LAYER4_PROTOCOLS = {"TCP", "UDP", "IP", "IPV4", "IPV6", "UNKNOWN"}


def _merge_signals(existing: tuple[str, ...], incoming: tuple[str, ...]) -> tuple[str, ...]:
    merged: list[str] = []
    seen: set[str] = set()
    for signal in (*existing, *incoming):
        text = str(signal or "").strip()
        if text and text not in seen:
            seen.add(text)
            merged.append(text)
    return tuple(merged)


@dataclass(slots=True)
class FlowState:
    start_time: float
    last_seen: float
    last_flushed: float
    packet_count: int
    byte_count: int
    domain: Optional[str] = None
    sni: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    application_protocol: Optional[str] = None
    service_name: Optional[str] = None
    analysis_source: str = "transport_fallback"
    analysis_confidence: float = 0.0
    analysis_signals: tuple[str, ...] = ()
    is_new: bool = True
    vlan_id: int = 0
    fwd_bytes: int = 0
    rev_bytes: int = 0
    fwd_packets: int = 0
    rev_packets: int = 0
    tcp_flags: Optional[str] = None
    is_closing: bool = False
    closing_at: Optional[float] = None
    priority_boost: bool = False
    orig_src_ip: str = ""
    orig_dst_ip: str = ""
    orig_src_port: int = 0
    orig_dst_port: int = 0

    @property
    def duration(self) -> float:
        if self.last_seen < self.start_time:
            return 0.0
        return self.last_seen - self.start_time

    @property
    def average_packet_size(self) -> float:
        if self.packet_count <= 0:
            return 0.0
        return self.byte_count / self.packet_count


@dataclass
class FlowSummary:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: str
    last_seen: str
    packet_count: int
    byte_count: int
    duration: float
    average_packet_size: float
    agent_id: str
    organization_id: str
    domain: Optional[str] = None
    sni: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    application_protocol: Optional[str] = None
    service_name: Optional[str] = None
    analysis_source: str = "transport_fallback"
    analysis_confidence: float = 0.0
    analysis_signals: tuple[str, ...] = ()
    source_type: str = "agent"
    metadata_only: bool = False
    event_type: str = "FLOW_UPDATE"
    vlan_id: int = 0
    fwd_bytes: int = 0
    rev_bytes: int = 0
    fwd_packets: int = 0
    rev_packets: int = 0
    tcp_flags: Optional[str] = None


class FlowManager:
    """
    16-Shard Lock-Partitioned Flow Aggregation Engine shared by agent and gateway runtimes.
    Partitioning active flows across 16 hash bucket locks reduces lock contention by ~93.75%.
    """
    NUM_SHARDS = 16

    def __init__(
        self,
        agent_id: str,
        organization_id: str,
        on_flow_expired: Callable[[FlowSummary], None],
        source_type: str = "agent",
        metadata_only: bool = False,
        tcp_timeout: int = 60,
        udp_timeout: int = 30,
        flush_interval: float = 5.0,
        max_flows: int = 50_000,
        cleanup_interval: float = 5.0,
        start_worker: bool = True,
    ) -> None:
        self.agent_id = agent_id
        self.organization_id = organization_id
        self.on_flow_expired = on_flow_expired
        self.source_type = str(source_type or "agent")
        self.metadata_only = bool(metadata_only)
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.flush_interval = flush_interval
        self.max_flows = max_flows
        self.cleanup_interval = cleanup_interval

        # 16 Sharded Dictionaries & Locks
        self._shards: list[Dict[FlowKey, FlowState]] = [{} for _ in range(self.NUM_SHARDS)]
        self._locks: list[threading.Lock] = [threading.Lock() for _ in range(self.NUM_SHARDS)]
        self._stop_event = threading.Event()

        self._worker_started = False
        if start_worker:
            worker = threading.Thread(target=self._expiry_worker, daemon=True)
            worker.start()
            self._worker_started = True

    def _get_shard_index(self, key: FlowKey) -> int:
        return abs(hash(key)) % self.NUM_SHARDS

    def stop(self) -> None:
        self._stop_event.set()

    def status_snapshot(self) -> dict:
        active_flows = 0
        oldest_seen = 0.0
        longest_lived = 0.0
        total_packets = 0
        total_bytes = 0
        now = time.time()

        for shard_idx in range(self.NUM_SHARDS):
            with self._locks[shard_idx]:
                active_flows += len(self._shards[shard_idx])
                for state in self._shards[shard_idx].values():
                    oldest_seen = max(oldest_seen, max(now - state.last_seen, 0.0))
                    longest_lived = max(longest_lived, max(now - state.start_time, 0.0))
                    total_packets += int(state.packet_count)
                    total_bytes += int(state.byte_count)

        return {
            "active_flow_count": active_flows,
            "max_flows": self.max_flows,
            "num_shards": self.NUM_SHARDS,
            "tcp_timeout_seconds": self.tcp_timeout,
            "udp_timeout_seconds": self.udp_timeout,
            "flush_interval_seconds": self.flush_interval,
            "cleanup_interval_seconds": self.cleanup_interval,
            "source_type": self.source_type,
            "metadata_only": self.metadata_only,
            "oldest_flow_age_seconds": round(oldest_seen, 3),
            "longest_flow_age_seconds": round(longest_lived, 3),
            "packet_count": total_packets,
            "byte_count": total_bytes,
        }

    def update_from_packet(self, packet) -> None:
        observation = PacketObservation.from_packet(
            packet,
            source_type=self.source_type,
            metadata_only=self.metadata_only,
        )
        if observation is None:
            return
        self.update_from_observation(observation)

    def update_from_observation(self, observation: PacketObservation) -> None:
        key: FlowKey = observation.canonical_conversation_key
        now = observation.observed_at
        size = observation.packet_size
        src_mac = observation.src_mac
        dst_mac = observation.dst_mac
        vlan_id = observation.vlan_id
        tcp_flags = observation.tcp_flags

        shard_idx = self._get_shard_index(key)
        max_per_shard = max(10, self.max_flows // self.NUM_SHARDS)

        with self._locks[shard_idx]:
            shard = self._shards[shard_idx]
            state = shard.get(key)
            if state is None:
                if len(shard) >= max_per_shard:
                    self._evict_oldest_shard_locked(shard)

                is_closing = False
                closing_at = None
                if tcp_flags and ("F" in tcp_flags or "R" in tcp_flags):
                    is_closing = True
                    closing_at = now

                is_control = False
                app_p = (observation.application_protocol or "").upper()
                svc_p = (observation.service_name or "").upper()
                if any(proto in app_p or proto in svc_p for proto in ("SMB", "KERBEROS", "LDAP", "CLDAP", "RDP", "DNS", "TLS", "HTTPS", "SSH")):
                    is_control = True

                shard[key] = FlowState(
                    start_time=now,
                    last_seen=now,
                    last_flushed=now,
                    packet_count=1,
                    byte_count=size,
                    domain=observation.domain,
                    sni=observation.sni,
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    application_protocol=observation.application_protocol,
                    service_name=observation.service_name,
                    analysis_source=observation.analysis_source,
                    analysis_confidence=observation.analysis_confidence,
                    analysis_signals=observation.analysis_signals,
                    vlan_id=vlan_id,
                    fwd_bytes=size,
                    rev_bytes=0,
                    fwd_packets=1,
                    rev_packets=0,
                    tcp_flags=tcp_flags,
                    is_closing=is_closing,
                    closing_at=closing_at,
                    priority_boost=is_control,
                    orig_src_ip=observation.src_ip,
                    orig_dst_ip=observation.dst_ip,
                    orig_src_port=observation.src_port,
                    orig_dst_port=observation.dst_port,
                )
            else:
                state.last_seen = now
                state.packet_count += 1
                state.byte_count += size
                is_fwd = (observation.is_forward_direction == state.forward_is_original_src)
                if is_fwd:
                    state.fwd_bytes += size
                    state.fwd_packets += 1
                else:
                    state.rev_bytes += size
                    state.rev_packets += 1
                if tcp_flags:
                    state.tcp_flags = tcp_flags
                    if "F" in tcp_flags or "R" in tcp_flags:
                        state.is_closing = True
                        if state.closing_at is None:
                            state.closing_at = now
                if vlan_id and not state.vlan_id:
                    state.vlan_id = vlan_id
                if observation.domain:
                    state.domain = observation.domain
                if observation.sni:
                    state.sni = observation.sni
                if is_fwd:
                    if src_mac:
                        state.src_mac = src_mac
                    if dst_mac:
                        state.dst_mac = dst_mac
                else:
                    if dst_mac:
                        state.src_mac = dst_mac
                    if src_mac:
                        state.dst_mac = src_mac
                if observation.application_protocol:
                    candidate_protocol = str(observation.application_protocol).strip().upper()
                    if candidate_protocol and (
                        not state.application_protocol
                        or state.application_protocol.upper() in GENERIC_LAYER4_PROTOCOLS
                        or candidate_protocol not in GENERIC_LAYER4_PROTOCOLS
                    ):
                        state.application_protocol = candidate_protocol
                if observation.service_name:
                    state.service_name = observation.service_name
                if observation.analysis_source:
                    if state.analysis_source == "transport_fallback" or observation.analysis_source != "transport_fallback":
                        state.analysis_source = observation.analysis_source
                if observation.analysis_confidence >= state.analysis_confidence:
                    state.analysis_confidence = observation.analysis_confidence
                state.analysis_signals = _merge_signals(state.analysis_signals, observation.analysis_signals)

    def _expiry_worker(self) -> None:
        print("[*] FlowManager 16-shard expiry worker started.")
        while not self._stop_event.is_set():
            try:
                self._expire_flows()
            except Exception as exc:
                print(f"ERROR in FlowManager expiry worker: {exc}")
            self._stop_event.wait(self.cleanup_interval)

    def _expire_flows(self) -> None:
        now = time.time()
        expired: Dict[FlowKey, Tuple[FlowState, str]] = {}
        flushed: Dict[FlowKey, Tuple[FlowState, str]] = {}

        for shard_idx in range(self.NUM_SHARDS):
            with self._locks[shard_idx]:
                shard = self._shards[shard_idx]
                for key, state in list(shard.items()):
                    proto = key[2] if isinstance(key[0], tuple) else key[4]
                    timeout = self.tcp_timeout if proto == "TCP" else self.udp_timeout
                    if state.is_closing and ((state.closing_at and now - state.closing_at >= 2.0) or (now - state.last_seen >= 2.0)):
                        expired[key] = (state, "FLOW_END")
                        del shard[key]
                    elif now - state.last_seen >= timeout:
                        expired[key] = (state, "FLOW_END")
                        del shard[key]
                    elif state.packet_count > 0 and now - state.last_flushed >= self.flush_interval:
                        event_type = "FLOW_NEW" if state.is_new else "FLOW_UPDATE"
                        flushed[key] = (FlowState(
                            start_time=state.start_time,
                            last_seen=state.last_seen,
                            last_flushed=state.last_flushed,
                            packet_count=state.packet_count,
                            byte_count=state.byte_count,
                            domain=state.domain,
                            sni=state.sni,
                            src_mac=state.src_mac,
                            dst_mac=state.dst_mac,
                            application_protocol=state.application_protocol,
                            service_name=state.service_name,
                            analysis_source=state.analysis_source,
                            analysis_confidence=state.analysis_confidence,
                            analysis_signals=state.analysis_signals,
                            is_new=state.is_new,
                            vlan_id=state.vlan_id,
                            fwd_bytes=state.fwd_bytes,
                            rev_bytes=state.rev_bytes,
                            fwd_packets=state.fwd_packets,
                            rev_packets=state.rev_packets,
                            tcp_flags=state.tcp_flags,
                            is_closing=state.is_closing,
                            closing_at=state.closing_at,
                            forward_is_original_src=state.forward_is_original_src,
                            orig_src_ip=state.orig_src_ip,
                            orig_dst_ip=state.orig_dst_ip,
                            orig_src_port=state.orig_src_port,
                            orig_dst_port=state.orig_dst_port,
                        ), event_type)
                        state.is_new = False
                        state.start_time = state.last_seen
                        state.last_flushed = now
                        state.packet_count = 0
                        state.byte_count = 0

        for collection in (flushed, expired):
            for key, val in collection.items():
                state, event_type = val
                summary = self._build_summary(key, state, event_type)
                try:
                    self.on_flow_expired(summary)
                except Exception:
                    continue

    def _build_summary(self, key: FlowKey, state: FlowState, event_type: str = "FLOW_UPDATE") -> FlowSummary:
        if isinstance(key[0], tuple):
            proto = key[2]
            src_ip = state.orig_src_ip or key[0][0]
            dst_ip = state.orig_dst_ip or key[0][1]
            sport = state.orig_src_port or key[1][0]
            dport = state.orig_dst_port or key[1][1]
        else:
            src_ip, dst_ip, sport, dport, proto = key
        start_dt = datetime.fromtimestamp(state.start_time, tz=timezone.utc)
        last_dt = datetime.fromtimestamp(state.last_seen, tz=timezone.utc)

        return FlowSummary(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            protocol=proto,
            start_time=start_dt.isoformat(),
            last_seen=last_dt.isoformat(),
            packet_count=state.packet_count,
            byte_count=state.byte_count,
            duration=state.duration,
            average_packet_size=state.average_packet_size,
            domain=state.domain,
            sni=state.sni,
            src_mac=state.src_mac,
            dst_mac=state.dst_mac,
            application_protocol=state.application_protocol,
            service_name=state.service_name,
            analysis_source=state.analysis_source,
            analysis_confidence=state.analysis_confidence,
            analysis_signals=state.analysis_signals,
            agent_id=self.agent_id,
            organization_id=self.organization_id,
            source_type=self.source_type,
            metadata_only=self.metadata_only,
            event_type=event_type,
            vlan_id=state.vlan_id,
            fwd_bytes=state.fwd_bytes,
            rev_bytes=state.rev_bytes,
            fwd_packets=state.fwd_packets,
            rev_packets=state.rev_packets,
            tcp_flags=state.tcp_flags,
        )

    def _evict_oldest_shard_locked(self, shard: Dict[FlowKey, FlowState]) -> None:
        if not shard:
            return

        batch_size = max(1, len(shard) // 10)
        oldest = heapq.nsmallest(batch_size, shard.items(), key=lambda kv: kv[1].last_seen)
        for key, _ in oldest:
            shard.pop(key, None)

