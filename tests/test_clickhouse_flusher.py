import os
import shutil
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backend.services.clickhouse_flusher import (
    CLICKHOUSE_FLOW_COLUMNS,
    ClickHouseDoubleBufferFlusher,
    DiskSpoolWAL,
)
from backend.services.clickhouse_analytics import ClickHouseAnalyticsBridge


@pytest.fixture
def temp_spool_dir(tmp_path):
    spool_dir = tmp_path / "clickhouse_spool"
    spool_dir.mkdir(parents=True, exist_ok=True)
    return str(spool_dir)


def _make_dummy_flow_row(idx=1):
    now = datetime.now(timezone.utc)
    return (
        "org-test",
        f"192.168.1.{idx}",
        f"10.0.0.{idx}",
        443,
        50000 + idx,
        "TCP",
        now,
        now,
        10,
        1500,
        0.5,
        150.0,
        "example.com",
        "example.com",
        "00:11:22:33:44:55",
        "66:77:88:99:AA:BB",
        "internal",
        "outbound",
        f"192.168.1.{idx}",
        f"10.0.0.{idx}",
        "sess-123",
        "HTTPS",
        "agent-1",
        "engine",
        0.95,
        "[]",
        f"hash-{idx}",
    )


class TestDiskSpoolWAL:
    def test_spool_batch_and_pending_count(self, temp_spool_dir):
        wal = DiskSpoolWAL(spool_dir=temp_spool_dir, max_files=10)
        assert wal.pending_count() == 0

        rows = [_make_dummy_flow_row(i) for i in range(5)]
        success = wal.spool_batch(rows)
        assert success is True
        assert wal.pending_count() == 1

        wal_files = list(Path(temp_spool_dir).glob("*.wal"))
        assert len(wal_files) == 1
        assert wal_files[0].stat().st_size > 0

    def test_spool_max_files_eviction(self, temp_spool_dir):
        wal = DiskSpoolWAL(spool_dir=temp_spool_dir, max_files=3)
        for i in range(5):
            wal.spool_batch([_make_dummy_flow_row(i)])
            time.sleep(0.01)

        # Should be capped at max_files (3)
        assert wal.pending_count() == 3

    def test_drain_spool_successful(self, temp_spool_dir):
        wal = DiskSpoolWAL(spool_dir=temp_spool_dir)
        rows1 = [_make_dummy_flow_row(1), _make_dummy_flow_row(2)]
        rows2 = [_make_dummy_flow_row(3)]
        wal.spool_batch(rows1)
        wal.spool_batch(rows2)
        assert wal.pending_count() == 2

        mock_client = MagicMock()
        drained_count = wal.drain_spool(mock_client, max_files=5)

        assert drained_count == 3
        assert wal.pending_count() == 0
        assert mock_client.insert.call_count == 2
        call_args = mock_client.insert.call_args_list[0]
        assert call_args[0][0] == "flow_logs"
        assert len(call_args[0][1]) == 2
        assert call_args[1]["column_names"] == CLICKHOUSE_FLOW_COLUMNS


class TestClickHouseDoubleBufferFlusher:
    def test_buffer_enqueue_and_swap(self, temp_spool_dir):
        flusher = ClickHouseDoubleBufferFlusher(
            batch_size=10,
            flush_interval_seconds=10.0,
            spool_dir=temp_spool_dir,
        )
        assert len(flusher._active_buffer) == 0

        rows = [_make_dummy_flow_row(i) for i in range(4)]
        flusher.enqueue(rows)
        assert len(flusher._active_buffer) == 4

        detached = flusher._swap_buffer()
        assert len(detached) == 4
        assert len(flusher._active_buffer) == 0

    def test_persist_chunk_success(self, temp_spool_dir):
        flusher = ClickHouseDoubleBufferFlusher(spool_dir=temp_spool_dir)
        mock_client = MagicMock()

        with patch("backend.db.clickhouse_client.get_clickhouse_client", return_value=mock_client):
            rows = [_make_dummy_flow_row(1)]
            result = flusher._persist_chunk(rows)
            assert result is True
            mock_client.insert.assert_called_once()
            assert flusher.spool.pending_count() == 0

    def test_persist_chunk_fallback_to_wal_on_failure(self, temp_spool_dir):
        flusher = ClickHouseDoubleBufferFlusher(spool_dir=temp_spool_dir)

        # Mock get_clickhouse_client to throw an operational exception
        with patch("backend.db.clickhouse_client.get_clickhouse_client", side_effect=Exception("ClickHouse offline")):
            rows = [_make_dummy_flow_row(1), _make_dummy_flow_row(2)]
            result = flusher._persist_chunk(rows)
            # Circuit breaker catches exception and writes to disk spool
            assert result is True
            assert flusher.spool.pending_count() == 1

    def test_background_worker_threshold_flush(self, temp_spool_dir):
        flusher = ClickHouseDoubleBufferFlusher(
            batch_size=5,
            flush_interval_seconds=5.0,
            spool_dir=temp_spool_dir,
        )
        mock_client = MagicMock()

        with patch("backend.db.clickhouse_client.get_clickhouse_client", return_value=mock_client):
            flusher.start()
            try:
                # Enqueue below threshold
                flusher.enqueue([_make_dummy_flow_row(1), _make_dummy_flow_row(2)])
                time.sleep(0.1)
                assert mock_client.insert.call_count == 0

                # Enqueue crossing threshold (total >= 5)
                flusher.enqueue([_make_dummy_flow_row(3), _make_dummy_flow_row(4), _make_dummy_flow_row(5)])
                # Give worker loop time to wake up on trigger
                time.sleep(0.3)
                assert mock_client.insert.call_count >= 1
            finally:
                flusher.shutdown()


class TestClickHouseAnalyticsBridge:
    def test_is_available_when_offline(self):
        bridge = ClickHouseAnalyticsBridge()
        with patch("backend.db.clickhouse_client.get_clickhouse_client", side_effect=Exception("Offline")):
            assert bridge.is_available() is False

    def test_query_dashboard_flow_stats_fallback(self):
        bridge = ClickHouseAnalyticsBridge()
        with patch("backend.db.clickhouse_client.get_clickhouse_client", side_effect=Exception("Offline")):
            assert bridge.query_dashboard_flow_stats("org-123") is None

    def test_query_dashboard_flow_stats_success(self):
        bridge = ClickHouseAnalyticsBridge()
        mock_client = MagicMock()
        mock_res_24h = MagicMock()
        mock_res_24h.result_rows = [[1250, 98765432]]
        mock_res_1m = MagicMock()
        mock_res_1m.result_rows = [[120000]]

        mock_client.query.side_effect = [mock_res_24h, mock_res_1m]

        with patch("backend.db.clickhouse_client.get_clickhouse_client", return_value=mock_client):
            stats = bridge.query_dashboard_flow_stats("org-123")
            assert stats is not None
            assert stats["flows_24h"] == 1250
            assert stats["bytes_24h"] == 98765432
            assert stats["bandwidth_bytes"] == 120000

    def test_query_device_rollup_success(self):
        bridge = ClickHouseAnalyticsBridge()
        mock_client = MagicMock()
        mock_res = MagicMock()
        mock_res.result_rows = [
            ["192.168.1.10", 500, 1048576, 12, datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)]
        ]
        mock_client.query.return_value = mock_res

        with patch("backend.db.clickhouse_client.get_clickhouse_client", return_value=mock_client):
            devices = bridge.query_device_rollup("org-123", hours=24, limit=10)
            assert devices is not None
            assert len(devices) == 1
            assert devices[0]["device_ip"] == "192.168.1.10"
            assert devices[0]["flow_count"] == 500
            assert devices[0]["bandwidth_bytes"] == 1048576
            assert devices[0]["distinct_targets"] == 12
