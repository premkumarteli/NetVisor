"""Tests for agent.upload.UploadManager health tracking."""

import pytest
from unittest.mock import MagicMock, patch

from agent.upload import UploadManager


@pytest.fixture
def mock_api_client():
    client = MagicMock()
    return client


@pytest.fixture
def upload_manager(mock_api_client, tmp_path):
    return UploadManager(
        api_client=mock_api_client,
        upload_url="http://localhost:8000/api/v1/collect/flow/batch",
        buffer_db_path=tmp_path / "buffer.db",
        buffer_max_mb=1,
        max_batch_size=5,
        max_wait_seconds=2,
        max_memory=100,
    )


class TestUploadManagerHealth:
    def test_initial_health_snapshot(self, upload_manager):
        snap = upload_manager.health_snapshot()
        assert snap["upload_failures"] == 0
        assert snap["upload_successes"] == 0
        assert snap["last_upload_time"] is None
        assert snap["last_upload_error"] is None
        assert snap["queue_depth"] == 0
        assert snap["consecutive_failures"] == 0

    def test_success_increments(self, upload_manager, mock_api_client):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_api_client.request.return_value = mock_response

        result = upload_manager._send_batch([{"test": "data"}])
        assert result is True

        snap = upload_manager.health_snapshot()
        assert snap["upload_successes"] == 1
        assert snap["upload_failures"] == 0
        assert snap["consecutive_failures"] == 0
        assert snap["last_upload_time"] is not None
        assert snap["last_upload_error"] is None

    def test_failure_increments(self, upload_manager, mock_api_client):
        mock_api_client.request.side_effect = ConnectionError("refused")

        result = upload_manager._send_batch([{"test": "data"}])
        assert result is False

        snap = upload_manager.health_snapshot()
        assert snap["upload_failures"] == 1
        assert snap["upload_successes"] == 0
        assert snap["consecutive_failures"] == 1
        assert snap["last_upload_error"] is not None

    def test_consecutive_failures_reset_on_success(self, upload_manager, mock_api_client):
        # Two failures
        mock_api_client.request.side_effect = ConnectionError("refused")
        upload_manager._send_batch([{"test": "data"}])
        upload_manager._send_batch([{"test": "data"}])
        assert upload_manager.health_snapshot()["consecutive_failures"] == 2

        # One success
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_api_client.request.side_effect = None
        mock_api_client.request.return_value = mock_response
        upload_manager._send_batch([{"test": "data"}])

        snap = upload_manager.health_snapshot()
        assert snap["consecutive_failures"] == 0
        assert snap["upload_failures"] == 2
        assert snap["upload_successes"] == 1

    def test_queue_depth_reflects_enqueue(self, upload_manager):
        upload_manager.enqueue_record({"test": "data"})
        assert upload_manager.health_snapshot()["queue_depth"] == 1

    def test_enqueue_returns_false_when_db_fails(self, tmp_path):
        client = MagicMock()
        manager = UploadManager(
            api_client=client,
            upload_url="http://localhost:8000/test",
            buffer_db_path=tmp_path / "buffer.db",
            buffer_max_mb=1,
            max_memory=1,
        )
        assert manager.enqueue_record({"first": True}) is True
        
        # Force a failure for the next spill to disk by breaking the connection
        manager.buffer.close()
        # This one goes to disk because memory (size 1) is full, but db is closed so it returns False
        assert manager.enqueue_record({"second": True}) is False
