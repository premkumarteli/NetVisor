from __future__ import annotations

import asyncio

from app.api import system as system_api


class _Connection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _run(awaitable):
    return asyncio.run(awaitable)


def test_get_system_status_preserves_flat_and_nested_runtime_fields(monkeypatch):
    conn = _Connection()

    monkeypatch.setattr(system_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(system_api.system_service, "get_runtime_status", lambda _conn: {"active": True, "maintenance_mode": False})
    monkeypatch.setattr(system_api.release_service, "snapshot", lambda: {"release_version": "2026.04.19"})
    monkeypatch.setattr(system_api.system_service, "latest_backup_status", lambda: {"verified": True})
    monkeypatch.setattr(system_api.system_service, "backup_retention_status", lambda: {"configured": True, "retention_days": 30})

    payload = _run(system_api.get_system_status(current_user={"role": "org_admin"}))

    assert payload["active"] is True
    assert payload["maintenance_mode"] is False
    assert payload["runtime"] == {"active": True, "maintenance_mode": False}
    assert payload["release"] == {"release_version": "2026.04.19"}
    assert payload["backup"] == {"verified": True}
    assert payload["backup_retention"] == {"configured": True, "retention_days": 30}
    assert conn.closed is True


def test_reset_data(monkeypatch):
    conn = _Connection()
    monkeypatch.setattr(system_api, "get_db_connection", lambda: conn)
    
    called_args = []
    def mock_reset_operational_data(db_conn, username, organization_id, ip_address):
        called_args.append((db_conn, username, organization_id, ip_address))
        return {
            "status": "success",
            "message": "Cleared 5 runtime row(s).",
            "backup_dir": "/tmp/backup",
            "cleared_tables": {"flow_logs": 5}
        }
        
    monkeypatch.setattr(system_api.system_service, "reset_operational_data", mock_reset_operational_data)
    
    class MockRequest:
        def __init__(self):
            self.headers = {"X-Real-IP": "192.168.1.50"}
            self.client = None
            
    request = MockRequest()
    
    current_user = {"username": "test_admin", "role": "org_admin", "organization_id": "org_123"}
    payload = _run(system_api.reset_data(request=request, current_user=current_user))
    
    assert payload["status"] == "success"
    assert payload["cleared_tables"] == {"flow_logs": 5}
    assert conn.closed is True
    assert len(called_args) == 1
    assert called_args[0][1] == "test_admin"
    assert called_args[0][2] == "org_123"
    assert called_args[0][3] == "192.168.1.50"

