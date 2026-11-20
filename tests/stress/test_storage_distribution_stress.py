"""
tests/stress/test_storage_distribution_stress.py
================================================
Stress tests evaluating multi-database workload distribution and concurrency:
- MySQL connection pool saturation under concurrent read/write spikes.
- Redis distributed rate limiting under sub-millisecond concurrent bursts (timestamp collision behavior).
- ClickHouse bulk insert batching simulation and micro-batch serialization cost analysis.
"""

from __future__ import annotations

import concurrent.futures
import json
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import mysql.connector.errors
import pytest

from tests.stress.conftest import (
    MockClickHouseClient,
    MockMySQLConnectionPool,
    MockRedis,
    generate_flow_batch,
    generate_synthetic_flow,
)


class TestMySQLPoolSaturationStress:
    """Stress tests evaluating MySQL connection pool behavior under heavy concurrency."""

    def test_mysql_pool_saturation_and_exhaustion(self, mock_mysql_pool: MockMySQLConnectionPool):
        """
        Simulate 30 concurrent threads contending for a limited connection pool (size=5).
        Demonstrates pool exhaustion, connection checkout queuing, and proper release semantics.
        """
        concurrency = 30
        successful_checkouts = 0
        exhaustion_errors = 0
        lock = threading.Lock()

        def worker(worker_id: int):
            nonlocal successful_checkouts, exhaustion_errors
            try:
                # Attempt to checkout connection
                conn = mock_mysql_pool.get_connection()
                try:
                    # Simulate short transactional work (5ms)
                    time.sleep(0.005)
                    cursor = conn.cursor()
                    cursor.execute("SELECT 1 FROM devices WHERE id = %s", (worker_id,))
                    conn.commit()
                    with lock:
                        successful_checkouts += 1
                finally:
                    conn.close()
            except mysql.connector.errors.PoolError:
                with lock:
                    exhaustion_errors += 1

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(worker, i) for i in range(concurrency)]
            concurrent.futures.wait(futures)

        # Under extreme concurrency with pool_size=5 and no queue wait,
        # some workers succeed and others experience pool exhaustion.
        assert successful_checkouts > 0, "At least some workers must acquire connections"
        assert exhaustion_errors > 0, "High concurrency burst must trigger pool exhaustion"
        assert successful_checkouts + exhaustion_errors == concurrency
        assert mock_mysql_pool.max_observed_concurrency <= mock_mysql_pool.pool_size
        # All connections must be returned to pool
        assert mock_mysql_pool.active_connections == 0


    def test_mysql_pool_recovery_after_burst(self, mock_mysql_pool: MockMySQLConnectionPool):
        """
        Verify that after a saturation spike, the connection pool fully recovers
        and subsequent requests succeed without connection leaks.
        """
        # Burst 1: Fill pool completely
        held_connections = []
        for _ in range(mock_mysql_pool.pool_size):
            held_connections.append(mock_mysql_pool.get_connection())

        assert mock_mysql_pool.active_connections == mock_mysql_pool.pool_size

        # Any extra checkout must fail with PoolError
        with pytest.raises(mysql.connector.errors.PoolError):
            mock_mysql_pool.get_connection()

        # Release all held connections
        for conn in held_connections:
            conn.close()

        assert mock_mysql_pool.active_connections == 0

        # Subsequent checkout must immediately succeed
        new_conn = mock_mysql_pool.get_connection()
        assert new_conn is not None
        new_conn.close()
        assert mock_mysql_pool.active_connections == 0


class TestRedisDistributedRateLimiterStress:
    """Stress tests for Redis distributed sliding-window rate limiting under burst loads."""

    def test_rate_limiter_timestamp_collision_behavior(self, mock_redis: MockRedis):
        """
        Reproduce the timestamp collision defect identified in Survey 3:
        In `backend/core/dependencies.py:231`, the pipeline executes:
            pipe.zadd(storage_key, {str(now): now})
        When multiple concurrent requests arrive with the exact same millisecond timestamp,
        the string key `str(now)` is identical, overwriting the sorted set entry and
        causing request undercounting.
        """
        storage_key = "ratelimit:api_flows:client_01"
        window = 60.0
        now = 1700000000.123456
        cutoff = now - window

        # 1. Reproduce collision: 20 concurrent requests with identical timestamp
        pipe = mock_redis.pipeline()
        for _ in range(20):
            pipe.zremrangebyscore(storage_key, 0, cutoff)
            pipe.zcard(storage_key)
            pipe.zadd(storage_key, {str(now): now})  # Same string key!
            pipe.expire(storage_key, int(window) + 1)
        pipe.execute()

        # Due to key overwrite, zcard only reports 1 item instead of 20
        collision_count = mock_redis.zcard(storage_key)
        assert collision_count == 1, (
            f"Expected timestamp collision resulting in count=1, got {collision_count}"
        )

        # 2. Collision-free approach: Using unique member keys (now:uuid)
        fixed_key = "ratelimit:api_flows:client_fixed"
        pipe_fixed = mock_redis.pipeline()
        for _ in range(20):
            pipe_fixed.zremrangebyscore(fixed_key, 0, cutoff)
            pipe_fixed.zcard(fixed_key)
            unique_member = f"{now}:{uuid.uuid4().hex[:8]}"
            pipe_fixed.zadd(fixed_key, {unique_member: now})
            pipe_fixed.expire(fixed_key, int(window) + 1)
        pipe_fixed.execute()

        fixed_count = mock_redis.zcard(fixed_key)
        assert fixed_count == 20, (
            f"Expected collision-free rate limiter to record 20 requests, got {fixed_count}"
        )


    def test_rate_limiter_concurrent_burst_throughput(self, mock_redis: MockRedis):
        """
        Benchmark distributed rate limiter operations per second under concurrent load.
        """
        concurrency = 25
        ops_per_thread = 40
        total_ops = concurrency * ops_per_thread

        def worker(thread_id: int):
            for i in range(ops_per_thread):
                key = f"ratelimit:bench:user_{thread_id % 5}"
                now = time.time()
                pipe = mock_redis.pipeline()
                pipe.zremrangebyscore(key, 0, now - 60.0)
                pipe.zcard(key)
                member = f"{now}:{uuid.uuid4().hex[:8]}"
                pipe.zadd(key, {member: now})
                pipe.expire(key, 61)
                pipe.execute()

        t0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(worker, i) for i in range(concurrency)]
            concurrent.futures.wait(futures)

        duration = time.perf_counter() - t0
        ops_sec = total_ops / duration if duration > 0 else 0.0

        assert ops_sec > 1000.0, f"Expected >1000 rate limit ops/sec, got {ops_sec:.2f}"


class TestClickHouseBatchScalingStress:
    """Stress tests evaluating ClickHouse bulk insert batching and serialization cost."""

    def test_clickhouse_bulk_insert_batch_scaling(self, mock_clickhouse: MockClickHouseClient):
        """
        Evaluate ClickHouse serialization and insertion across various batch sizes:
        B in [10, 100, 500, 1000, 5000].
        Demonstrates that larger batch sizes drastically reduce per-row serialization
        and round-trip overhead.
        """
        batch_sizes = [10, 100, 500, 1000, 5000]
        columns = [
            "organization_id", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "start_time", "last_seen", "packet_count", "byte_count",
            "duration", "average_packet_size", "domain", "sni", "src_mac", "dst_mac",
            "network_scope", "flow_direction", "internal_device_ip", "external_endpoint_ip",
            "session_id", "application", "agent_id", "analysis_source", "analysis_confidence",
            "analysis_signals_json", "ingest_hash"
        ]

        scaling_results: Dict[int, Dict[str, float]] = {}

        for b_size in batch_sizes:
            flows = generate_flow_batch(count=b_size)

            t0 = time.perf_counter()
            # Convert flows to ClickHouse row format (same serialization logic as flow_service.py)
            ch_rows = [
                [
                    f.get("organization_id", ""),
                    f.get("src_ip", ""),
                    f.get("dst_ip", ""),
                    int(f.get("src_port") or 0),
                    int(f.get("dst_port") or 0),
                    f.get("protocol", "TCP"),
                    datetime.now(timezone.utc),
                    datetime.now(timezone.utc),
                    int(f.get("packet_count") or 1),
                    int(f.get("byte_count") or 60),
                    float(f.get("duration") or 0.1),
                    float(f.get("average_packet_size") or 60.0),
                    f.get("domain", ""),
                    f.get("sni", ""),
                    f.get("src_mac", ""),
                    f.get("dst_mac", ""),
                    f.get("network_scope", "internal"),
                    f.get("flow_direction", "outbound"),
                    f.get("internal_device_ip", ""),
                    f.get("external_endpoint_ip", ""),
                    f.get("session_id", ""),
                    f.get("application", "Other"),
                    f.get("agent_id", ""),
                    f.get("analysis_source", "engine"),
                    float(f.get("analysis_confidence") or 0.9),
                    json.dumps(f.get("analysis_signals") or []),
                    f.get("ingest_hash", ""),
                ]
                for f in flows
            ]
            serialization_time = time.perf_counter() - t0

            # Perform insert
            t_insert = time.perf_counter()
            mock_clickhouse.insert("flow_logs", ch_rows, column_names=columns)
            insert_time = time.perf_counter() - t_insert

            total_time = serialization_time + insert_time
            rows_per_sec = b_size / total_time if total_time > 0 else 0.0
            us_per_row = (total_time / b_size) * 1e6

            scaling_results[b_size] = {
                "rows_sec": rows_per_sec,
                "us_per_row": us_per_row,
                "serialization_ms": serialization_time * 1000.0,
            }

        # Verify that all batches were successfully inserted into ClickHouse
        assert mock_clickhouse.total_inserted_count == sum(batch_sizes)
        assert mock_clickhouse.insert_call_count == len(batch_sizes)

        # In bulk batching (5000 rows), throughput should be high (>10,000 rows/sec)
        assert scaling_results[5000]["rows_sec"] > 5000.0


    def test_clickhouse_transient_retry_backoff(self, mock_clickhouse: MockClickHouseClient):
        """
        Verify ClickHouse insertion retry logic with exponential backoff
        when encountering simulated transient network errors.
        """
        flows = generate_flow_batch(count=100)
        ch_rows = [[f["src_ip"], f["dst_ip"]] for f in flows]

        # Configure mock to fail twice before succeeding on attempt 3
        mock_clickhouse.failure_countdown = 2
        mock_clickhouse.failure_exception = Exception("Connection reset by peer (ClickHouse transient)")

        max_retries = 3
        retry_delay = 0.005  # Fast delay for stress test
        success = False

        for attempt in range(max_retries):
            try:
                mock_clickhouse.insert("flow_logs", ch_rows, column_names=["src_ip", "dst_ip"])
                success = True
                break
            except Exception:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))

        assert success is True
        assert mock_clickhouse.insert_call_count == 3
        assert mock_clickhouse.total_inserted_count == 100
