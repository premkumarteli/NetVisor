"""
tests/stress/conftest.py
========================
High-volume mock packet and flow telemetry generators, plus isolated in-memory
mock infrastructure fixtures (Redis stream/pipeline, ClickHouse native client,
and MySQL connection pool). Enables deterministic, zero-external-daemon stress
and benchmark execution across CI/dev environments.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

import mysql.connector.errors
import pytest


# ---------------------------------------------------------------------------
# Telemetry Data Generators
# ---------------------------------------------------------------------------

COMMON_PORTS = [80, 443, 8080, 8443, 53, 22, 445, 88, 3389, 51820, 1194]
APPLICATIONS = [
    ("HTTPS", 443, "TCP"),
    ("HTTP", 80, "TCP"),
    ("DNS", 53, "UDP"),
    ("SSH", 22, "TCP"),
    ("SMB2", 445, "TCP"),
    ("KERBEROS", 88, "TCP"),
    ("RDP", 3389, "TCP"),
    ("WireGuard", 51820, "UDP"),
    ("OpenVPN", 1194, "UDP"),
]

BENIGN_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "cloudflare.com",
    "aws.amazon.com", "api.stripe.com", "cdn.jsdelivr.net", "slack.com"
]


def generate_synthetic_flow(flow_type: str = "benign", **overrides: Any) -> Dict[str, Any]:
    """
    Generate a single realistic network flow record compatible with NetVisor engines
    and ingestion pipelines.
    """
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    # Defaults
    src_ip = f"192.168.1.{random.randint(2, 254)}"
    dst_ip = f"104.16.{random.randint(1, 254)}.{random.randint(1, 254)}"
    app, dst_port, protocol = random.choice(APPLICATIONS[:3])
    src_port = random.randint(1024, 65535)
    packet_count = random.randint(5, 50)
    byte_count = packet_count * random.randint(60, 1400)
    domain = random.choice(BENIGN_DOMAINS)
    sni = domain
    analysis_signals: List[str] = []

    if flow_type == "port_scan":
        dst_ip = overrides.get("dst_ip", "192.168.1.100")
        dst_port = overrides.get("dst_port", random.randint(1, 1024))
        protocol = "TCP"
        packet_count = 1
        byte_count = 60
        domain = ""
        sni = ""

    elif flow_type == "c2_beacon":
        dst_ip = overrides.get("dst_ip", "198.51.100.42")
        dst_port = overrides.get("dst_port", 4444)
        protocol = "TCP"
        packet_count = random.randint(2, 4)
        byte_count = 128
        domain = "c2.evil-corp-test.xyz"
        sni = domain

    elif flow_type == "dns_tunnel":
        dst_ip = overrides.get("dst_ip", "8.8.8.8")
        dst_port = 53
        protocol = "UDP"
        random_hex = uuid.uuid4().hex[:20]
        domain = f"{random_hex}.tunnel.exfil-test.com"
        sni = ""
        analysis_signals = ["high_entropy_subdomain", "txt_record"]

    elif flow_type == "vpn_wireguard":
        dst_port = 51820
        protocol = "UDP"
        packet_count = random.randint(10, 100)
        byte_count = packet_count * 148
        domain = ""
        sni = ""
        analysis_signals = ["wireguard_handshake", "fixed_packet_size_148"]

    elif flow_type == "vpn_openvpn":
        dst_port = 1194
        protocol = "UDP"
        packet_count = random.randint(20, 200)
        byte_count = packet_count * 200
        domain = ""
        sni = ""
        analysis_signals = ["openvpn_control_channel"]

    elif flow_type == "kerberoasting":
        dst_ip = overrides.get("dst_ip", "192.168.1.10")
        dst_port = 88
        protocol = "TCP"
        app = "KERBEROS"
        domain = overrides.get("domain", f"MSSQLSvc/sql{random.randint(1, 9)}.corp.local:1433")
        analysis_signals = ["rc4_hmac", "etype_23", "tgs_req"]

    elif flow_type == "pass_the_hash":
        dst_ip = overrides.get("dst_ip", "192.168.1.50")
        dst_port = 445
        protocol = "TCP"
        app = "SMB2"
        analysis_signals = ["C$", "NTLMSSP_AUTH", "PSEXEC"]

    elif flow_type == "smb_lateral":
        dst_ip = overrides.get("dst_ip", f"192.168.1.{random.randint(10, 30)}")
        dst_port = 445
        protocol = "TCP"
        app = "SMB2"
        analysis_signals = ["IPC$", "TREE_CONNECT", "ADMIN$"]

    elif flow_type == "device_dhcp":
        src_port = 68
        dst_port = 67
        protocol = "UDP"
        analysis_signals = ["dhcp_request", "option55_1_3_6_15_119_252"]

    flow = {
        "organization_id": overrides.get("organization_id", "00000000-0000-0000-0000-000000000001"),
        "agent_id": overrides.get("agent_id", "agent-stress-01"),
        "source_type": overrides.get("source_type", "agent"),
        "src_ip": overrides.get("src_ip", src_ip),
        "dst_ip": overrides.get("dst_ip", dst_ip),
        "src_port": overrides.get("src_port", src_port),
        "dst_port": overrides.get("dst_port", dst_port),
        "protocol": overrides.get("protocol", protocol),
        "packet_count": overrides.get("packet_count", packet_count),
        "byte_count": overrides.get("byte_count", byte_count),
        "duration": overrides.get("duration", 0.5),
        "average_packet_size": overrides.get("average_packet_size", float(byte_count) / max(packet_count, 1)),
        "domain": overrides.get("domain", domain),
        "sni": overrides.get("sni", sni),
        "src_mac": overrides.get("src_mac", "aa:bb:cc:dd:ee:01"),
        "dst_mac": overrides.get("dst_mac", "aa:bb:cc:dd:ee:fe"),
        "network_scope": overrides.get("network_scope", "internal"),
        "flow_direction": overrides.get("flow_direction", "outbound"),
        "internal_device_ip": overrides.get("internal_device_ip", src_ip),
        "external_endpoint_ip": overrides.get("external_endpoint_ip", dst_ip),
        "session_id": overrides.get("session_id", uuid.uuid4().hex),
        "application": overrides.get("application", app),
        "application_protocol": overrides.get("application_protocol", app),
        "analysis_source": "stress_generator",
        "analysis_confidence": 0.95,
        "analysis_signals": analysis_signals,
        "timestamp": overrides.get("timestamp", now_iso),
        "start_time": overrides.get("start_time", now_iso),
        "last_seen": overrides.get("last_seen", now_iso),
        "created_at": now_iso,
    }

    # Ingest hash computation
    hash_str = f"{flow['organization_id']}:{flow['src_ip']}:{flow['dst_ip']}:{flow['src_port']}:{flow['dst_port']}:{flow['protocol']}:{flow['start_time']}"
    flow["ingest_hash"] = hashlib.sha256(hash_str.encode()).hexdigest()

    # Apply any custom overrides
    for k, v in overrides.items():
        flow[k] = v

    return flow


def generate_flow_batch(
    count: int = 1000,
    distribution: Optional[Dict[str, float]] = None,
    organization_id: str = "00000000-0000-0000-0000-000000000001",
) -> List[Dict[str, Any]]:
    """
    Generate a high-volume batch of synthetic flows according to a specified
    or realistic default distribution.
    """
    if distribution is None:
        distribution = {
            "benign": 0.80,
            "port_scan": 0.05,
            "c2_beacon": 0.03,
            "dns_tunnel": 0.03,
            "vpn_wireguard": 0.02,
            "vpn_openvpn": 0.02,
            "kerberoasting": 0.02,
            "pass_the_hash": 0.01,
            "smb_lateral": 0.02,
        }

    types = list(distribution.keys())
    weights = list(distribution.values())

    batch: List[Dict[str, Any]] = []
    for _ in range(count):
        flow_type = random.choices(types, weights=weights, k=1)[0]
        batch.append(generate_synthetic_flow(flow_type=flow_type, organization_id=organization_id))

    return batch


# ---------------------------------------------------------------------------
# Isolated In-Memory Mock Redis (Streams, Hashes, Sorted Sets, Pipelines)
# ---------------------------------------------------------------------------

class MockRedisPipeline:
    """Thread-safe mock Redis pipeline executing atomic operations."""

    def __init__(self, redis_client: "MockRedis"):
        self._redis = redis_client
        self._commands: List[Tuple[str, tuple, dict]] = []

    def zremrangebyscore(self, name: str, min_score: float, max_score: float):
        self._commands.append(("zremrangebyscore", (name, min_score, max_score), {}))
        return self

    def zcard(self, name: str):
        self._commands.append(("zcard", (name,), {}))
        return self

    def zadd(self, name: str, mapping: Dict[str, float]):
        self._commands.append(("zadd", (name, mapping), {}))
        return self

    def expire(self, name: str, time_sec: int):
        self._commands.append(("expire", (name, time_sec), {}))
        return self

    def execute(self) -> List[Any]:
        results = []
        with self._redis._lock:
            for cmd, args, kwargs in self._commands:
                fn = getattr(self._redis, f"_{cmd}")
                results.append(fn(*args, **kwargs))
        self._commands.clear()
        return results


class MockRedis:
    """
    In-memory thread-safe mock of Redis 7.0 for streams, pipelines, and sorted sets.
    Accurately reproduces Redis stream semantics (consumer groups, PEL, ACK, DEL, XADD MAXLEN).
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._kv: Dict[str, Any] = {}
        self._ttls: Dict[str, float] = {}
        self._sorted_sets: Dict[str, Dict[str, float]] = {}
        # Streams: stream_name -> list of (msg_id, fields)
        self._streams: Dict[str, List[Tuple[str, Dict[str, str]]]] = {}
        # Consumer groups: stream_name -> group_name -> { "last_delivered_id": str, "pel": {msg_id: (consumer, timestamp, delivery_count)} }
        self._groups: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._seq = 0

    def pipeline(self) -> MockRedisPipeline:
        return MockRedisPipeline(self)

    # Key-Value
    def get(self, name: str) -> Optional[str]:
        with self._lock:
            self._purge_expired()
            return self._kv.get(name)

    def set(self, name: str, value: Any, ex: Optional[int] = None) -> bool:
        with self._lock:
            self._kv[name] = str(value)
            if ex:
                self._ttls[name] = time.time() + ex
            elif name in self._ttls:
                del self._ttls[name]
            return True

    def delete(self, *names: str) -> int:
        count = 0
        with self._lock:
            for name in names:
                if name in self._kv:
                    del self._kv[name]
                    count += 1
                if name in self._sorted_sets:
                    del self._sorted_sets[name]
                    count += 1
                if name in self._streams:
                    del self._streams[name]
                    count += 1
        return count

    # Sorted Sets (Used for Distributed Rate Limiter)
    def _zremrangebyscore(self, name: str, min_score: float, max_score: float) -> int:
        zset = self._sorted_sets.setdefault(name, {})
        to_del = [m for m, s in zset.items() if min_score <= s <= max_score]
        for m in to_del:
            del zset[m]
        return len(to_del)

    def _zcard(self, name: str) -> int:
        return len(self._sorted_sets.get(name, {}))

    def _zadd(self, name: str, mapping: Dict[str, float]) -> int:
        zset = self._sorted_sets.setdefault(name, {})
        added = 0
        for member, score in mapping.items():
            if member not in zset:
                added += 1
            zset[member] = float(score)
        return added

    def _expire(self, name: str, time_sec: int) -> bool:
        self._ttls[name] = time.time() + time_sec
        return True

    def zremrangebyscore(self, name: str, min_score: float, max_score: float) -> int:
        with self._lock:
            return self._zremrangebyscore(name, min_score, max_score)

    def zcard(self, name: str) -> int:
        with self._lock:
            return self._zcard(name)

    def zadd(self, name: str, mapping: Dict[str, float]) -> int:
        with self._lock:
            return self._zadd(name, mapping)

    def expire(self, name: str, time_sec: int) -> bool:
        with self._lock:
            return self._expire(name, time_sec)

    # Streams
    def xadd(
        self,
        name: str,
        fields: Dict[str, Any],
        id: str = "*",
        maxlen: Optional[int] = None,
        approximate: bool = False,
    ) -> str:
        with self._lock:
            self._seq += 1
            ts = int(time.time() * 1000)
            msg_id = f"{ts}-{self._seq}" if id == "*" else id

            # Ensure fields values are strings
            str_fields = {k: str(v) for k, v in fields.items()}
            stream = self._streams.setdefault(name, [])
            stream.append((msg_id, str_fields))

            if maxlen is not None and len(stream) > maxlen:
                excess = len(stream) - maxlen
                del stream[:excess]

            return msg_id

    def xlen(self, name: str) -> int:
        with self._lock:
            return len(self._streams.get(name, []))

    def xgroup_create(
        self, name: str, groupname: str, id: str = "$", mkstream: bool = False
    ) -> bool:
        with self._lock:
            if mkstream and name not in self._streams:
                self._streams[name] = []
            groups = self._groups.setdefault(name, {})
            groups[groupname] = {
                "last_delivered_id": "0-0" if id == "0" else (self._streams[name][-1][0] if self._streams.get(name) else "0-0"),
                "pel": {},  # msg_id -> (consumer, timestamp, delivery_count)
            }
            return True

    def xreadgroup(
        self,
        groupname: str,
        consumername: str,
        streams: Dict[str, str],
        count: Optional[int] = None,
        block: Optional[int] = None,
        noack: bool = False,
    ) -> List[List[Any]]:
        results = []
        with self._lock:
            for stream_name, read_id in streams.items():
                stream = self._streams.get(stream_name, [])
                group = self._groups.setdefault(stream_name, {}).setdefault(
                    groupname, {"last_delivered_id": "0-0", "pel": {}}
                )

                messages: List[Tuple[str, Dict[str, str]]] = []
                if read_id == ">":
                    # Read new undispatched messages
                    last_id = group["last_delivered_id"]
                    for mid, payload in stream:
                        if mid > last_id:
                            messages.append((mid, payload))
                            if count and len(messages) >= count:
                                break
                    if messages:
                        group["last_delivered_id"] = messages[-1][0]
                else:
                    # Read messages from PEL or given ID
                    for mid, payload in stream:
                        if mid > read_id:
                            messages.append((mid, payload))
                            if count and len(messages) >= count:
                                break

                # Track in PEL
                if not noack:
                    for mid, _ in messages:
                        curr = group["pel"].get(mid, (consumername, 0, 0))
                        group["pel"][mid] = (consumername, time.time(), curr[2] + 1)

                if messages:
                    results.append([stream_name, messages])

        return results

    def xack(self, name: str, groupname: str, *ids: str) -> int:
        with self._lock:
            group = self._groups.get(name, {}).get(groupname)
            if not group:
                return 0
            acked = 0
            for mid in ids:
                if mid in group["pel"]:
                    del group["pel"][mid]
                    acked += 1
            return acked

    def xdel(self, name: str, *ids: str) -> int:
        with self._lock:
            stream = self._streams.get(name, [])
            id_set = set(ids)
            initial_len = len(stream)
            self._streams[name] = [item for item in stream if item[0] not in id_set]
            return initial_len - len(self._streams[name])

    def xpending_range(
        self,
        name: str,
        groupname: str,
        min: str = "-",
        max: str = "+",
        count: int = 10,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            group = self._groups.get(name, {}).get(groupname)
            if not group:
                return []
            res = []
            for mid, (cname, ts, dcount) in list(group["pel"].items())[:count]:
                idle_ms = int((time.time() - ts) * 1000)
                res.append({
                    "message_id": mid,
                    "consumer": cname,
                    "idle_time": idle_ms,
                    "delivery_count": dcount,
                })
            return res

    def xclaim(
        self,
        name: str,
        groupname: str,
        consumername: str,
        min_idle_time: int,
        message_ids: List[str],
    ) -> List[Tuple[str, Dict[str, str]]]:
        with self._lock:
            group = self._groups.get(name, {}).get(groupname)
            if not group:
                return []
            claimed = []
            stream_dict = dict(self._streams.get(name, []))
            for mid in message_ids:
                if mid in group["pel"] and mid in stream_dict:
                    group["pel"][mid] = (consumername, time.time(), group["pel"][mid][2] + 1)
                    claimed.append((mid, stream_dict[mid]))
            return claimed

    def _purge_expired(self) -> None:
        now = time.time()
        expired = [k for k, exp in self._ttls.items() if now > exp]
        for k in expired:
            self._kv.pop(k, None)
            self._sorted_sets.pop(k, None)
            self._ttls.pop(k, None)


# ---------------------------------------------------------------------------
# Isolated Mock ClickHouse Client
# ---------------------------------------------------------------------------

class MockClickHouseClient:
    """
    Thread-safe mock ClickHouse client with configurable latency, row tracking,
    and failure injection for bulk insert stress tests.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.inserted_rows: List[List[Any]] = []
        self.inserted_tables: List[str] = []
        self.columns_recorded: List[List[str]] = []
        self.total_inserted_count = 0
        self.insert_call_count = 0
        self.simulate_latency_sec = 0.0
        self.failure_countdown = 0
        self.failure_exception = Exception("Simulated ClickHouse Network Timeout")

    def insert(
        self,
        table: str,
        data: List[Union[List[Any], Tuple[Any, ...]]],
        column_names: Optional[List[str]] = None,
    ) -> None:
        with self._lock:
            self.insert_call_count += 1
            if self.failure_countdown > 0:
                self.failure_countdown -= 1
                raise self.failure_exception

            if self.simulate_latency_sec > 0:
                time.sleep(self.simulate_latency_sec)

            self.inserted_tables.append(table)
            self.inserted_rows.extend(data)
            self.total_inserted_count += len(data)
            if column_names:
                self.columns_recorded.append(column_names)

    def command(self, query: str) -> None:
        pass

    def query(self, query: str):
        class MockQueryResult:
            def __init__(self):
                self.result_rows = []
        return MockQueryResult()

    def reset(self) -> None:
        with self._lock:
            self.inserted_rows.clear()
            self.inserted_tables.clear()
            self.columns_recorded.clear()
            self.total_inserted_count = 0
            self.insert_call_count = 0
            self.failure_countdown = 0


# ---------------------------------------------------------------------------
# Isolated Mock MySQL Pool & Connections
# ---------------------------------------------------------------------------

class MockMySQLCursor:
    """Mock MySQL cursor supporting execution and results."""

    def __init__(self, conn: "MockMySQLConnection"):
        self._conn = conn
        self.last_query = ""
        self.last_params = None
        self.rowcount = 1

    def execute(self, query: str, params: Any = None) -> None:
        self.last_query = query
        self.last_params = params

    def executemany(self, query: str, seq_params: Any = None) -> None:
        self.last_query = query
        self.last_params = seq_params
        self.rowcount = len(seq_params) if seq_params else 0

    def fetchone(self) -> Optional[Tuple]:
        return (1,)

    def fetchall(self) -> List[Tuple]:
        return [(1,)]

    def close(self) -> None:
        pass


class MockMySQLConnection:
    """Thread-safe mock MySQL connection with pool return semantics."""

    def __init__(self, pool: "MockMySQLConnectionPool", conn_id: int):
        self._pool = pool
        self.conn_id = conn_id
        self.is_closed = False
        self.autocommit = False

    def cursor(self, dictionary: bool = False) -> MockMySQLCursor:
        if self.is_closed:
            raise mysql.connector.errors.OperationalError("MySQL Connection is closed.")
        return MockMySQLCursor(self)

    def commit(self) -> None:
        if self.is_closed:
            raise mysql.connector.errors.OperationalError("MySQL Connection is closed.")

    def rollback(self) -> None:
        if self.is_closed:
            raise mysql.connector.errors.OperationalError("MySQL Connection is closed.")

    def close(self) -> None:
        if not self.is_closed:
            self.is_closed = True
            self._pool._return_connection(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class MockMySQLConnectionPool:
    """
    Thread-safe mock MySQL Connection Pool reproducing exact MySQL pool exhaustion
    and checkout behavior under concurrent load.
    """

    def __init__(self, pool_size: int = 5, pool_name: str = "stress_test_pool"):
        self.pool_size = pool_size
        self.pool_name = pool_name
        self._lock = threading.Lock()
        self._active_connections = 0
        self._total_checkouts = 0
        self._max_observed_concurrency = 0

    def get_connection(self) -> MockMySQLConnection:
        with self._lock:
            if self._active_connections >= self.pool_size:
                raise mysql.connector.errors.PoolError(
                    f"Failed getting connection; pool exhausted (max={self.pool_size}, active={self._active_connections})"
                )
            self._active_connections += 1
            self._total_checkouts += 1
            if self._active_connections > self._max_observed_concurrency:
                self._max_observed_concurrency = self._active_connections
            return MockMySQLConnection(self, self._total_checkouts)

    def _return_connection(self, conn: MockMySQLConnection) -> None:
        with self._lock:
            if self._active_connections > 0:
                self._active_connections -= 1

    @property
    def active_connections(self) -> int:
        with self._lock:
            return self._active_connections

    @property
    def max_observed_concurrency(self) -> int:
        with self._lock:
            return self._max_observed_concurrency


# ---------------------------------------------------------------------------
# Pytest Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_redis() -> MockRedis:
    """Fixture providing an isolated in-memory MockRedis instance."""
    return MockRedis()


@pytest.fixture
def mock_clickhouse() -> MockClickHouseClient:
    """Fixture providing an isolated in-memory MockClickHouseClient instance."""
    client = MockClickHouseClient()
    client.reset()
    return client


@pytest.fixture
def mock_mysql_pool() -> MockMySQLConnectionPool:
    """Fixture providing a bounded MockMySQLConnectionPool (size=5) for saturation tests."""
    return MockMySQLConnectionPool(pool_size=5)


@pytest.fixture
def sample_flow() -> Dict[str, Any]:
    """Fixture providing a single standardized benign flow."""
    return generate_synthetic_flow("benign")


@pytest.fixture
def sample_flow_batch() -> List[Dict[str, Any]]:
    """Fixture providing a batch of 100 realistic heterogeneous flows."""
    return generate_flow_batch(count=100)
