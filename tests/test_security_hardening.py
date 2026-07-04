import os
import json
import secrets
import tempfile
from pathlib import Path

import pytest
from fastapi import HTTPException

# Test targets
from agent.security.dpapi import FileProtector, DynamicProtector
from agent.dpi.redaction import redact_url
from app.core.config import settings
from app.services.device_service import device_service
from app.services.alert_service import alert_service
from app.services.agent_enrollment_service import agent_enrollment_service
from app.services.system_service import system_service


# --- 1. Test FileProtector & DynamicProtector ---

def test_file_protector_lifecycle(tmp_path):
    key_file = tmp_path / "test_agent_key.bin"
    protector = FileProtector(key_path=key_file)
    
    plaintext = b"supersecretcredentials"
    encrypted = protector.protect(plaintext)
    
    assert encrypted.startswith(b"v1:")
    assert encrypted != plaintext
    
    decrypted = protector.unprotect(encrypted)
    assert decrypted == plaintext
    
    # Check key file creation and contents
    assert key_file.exists()
    assert len(key_file.read_bytes()) == 32
    
    # Ensure permission locks (0o600 on Unix)
    if os.name != "nt":
        mode = key_file.stat().st_mode & 0o777
        assert mode == 0o600


def test_dynamic_protector_fallbacks(tmp_path):
    key_file = tmp_path / "dynamic_key.bin"
    dynamic = DynamicProtector(key_path=key_file)
    
    plaintext = b"someagentsecret"
    encrypted = dynamic.protect(plaintext)
    
    # On non-Windows platforms, it will use FileProtector
    if os.name != "nt":
        assert encrypted.startswith(b"v1:")
        
    decrypted = dynamic.unprotect(encrypted)
    assert decrypted == plaintext


def test_dynamic_protector_legacy_unix_json_fallback(tmp_path):
    dynamic = DynamicProtector(key_path=tmp_path / "k.bin")
    
    # On Unix, if it receives legacy unencrypted JSON, it should bypass decryption and return it directly
    legacy_json = b'{"agent_id": "test", "token": "abc"}'
    
    if os.name != "nt":
        result = dynamic.unprotect(legacy_json)
        assert result == legacy_json


# --- 2. Test URL Redaction Heuristics ---

def test_url_redaction_paths_and_tokens():
    # 1. Reset password path
    url1 = "https://netvisor.local/reset-password/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
    redacted1 = redact_url(url1)
    assert "/reset-password/[REDACTED]" in redacted1
    
    # 2. Verify token path
    url2 = "https://netvisor.local/verify/abc123token456longsecretkeyhere"
    redacted2 = redact_url(url2)
    assert "/verify/[REDACTED]" in redacted2
    
    # 3. JWT parameter redaction
    jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    url3 = f"https://netvisor.local/api/v1/auth?jwt={jwt_token}"
    redacted3 = redact_url(url3)
    assert "jwt=%5BREDACTED%5D" in redacted3
    
    # 4. UUID parameter redaction
    url4 = "https://netvisor.local/api/v1/devices?device_id=9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
    redacted4 = redact_url(url4)
    assert "device_id=%5BREDACTED%5D" in redacted4


# --- 3. Test Scoping & Tenant Isolation ---

class FakeCursor:
    def __init__(self):
        self.queries = []
        self.params_list = []
        self.rowcount = 1
        self.column_names = ("id", "organization_id", "device_id", "current_score", "risk_level", "reasons")

    def execute(self, query, params=None):
        self.query = " ".join(query.strip().split())
        self.params = params
        self.queries.append(self.query)
        self.params_list.append(self.params or ())

    def fetchone(self):
        return {"device_id": "192.168.1.10", "organization_id": "org-a", "current_score": 75}

    def fetchall(self):
        return [{"device_id": "192.168.1.10", "current_score": 75}]

    def fetchmany(self, size=1000):
        # Return empty list to break loops in system_service csv exports
        return []

    def close(self):
        pass


class FakeConnection:
    def __init__(self):
        self.cursor_obj = FakeCursor()
        self.committed = False
        self.rolledback = False

    def cursor(self, dictionary=False):
        return self.cursor_obj

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolledback = True

    def close(self):
        pass


@pytest.fixture(autouse=True)
def force_multi_org_mode(monkeypatch):
    monkeypatch.setattr(settings, "SINGLE_ORG_MODE", False)


def test_device_risk_tenant_filtering():
    fake_conn = FakeConnection()
    
    # 1. Fetch risk with org scoping
    device_service.get_device_risk(fake_conn, "192.168.1.10", "org-a")
    assert "organization_id = %s" in fake_conn.cursor_obj.query
    assert fake_conn.cursor_obj.params == ("192.168.1.10", "org-a")


def test_alert_risk_ranking_tenant_filtering():
    fake_conn = FakeConnection()
    
    # 1. Fetch ranking with org scoping
    alert_service.get_risk_ranking(fake_conn, "org-a", limit=5)
    assert "WHERE organization_id = %s" in fake_conn.cursor_obj.query
    assert fake_conn.cursor_obj.params == ("org-a", 5)


def test_agent_enrollment_tenant_scoping():
    fake_conn = FakeConnection()
    
    # 1. Scoped approval
    agent_enrollment_service.approve_request(
        fake_conn,
        request_id="req-123",
        reviewed_by="admin-user",
        review_reason="Looks good",
        organization_id="org-a",
    )
    # Check that UPDATE query scopes by organization_id
    update_queries = [q for q in fake_conn.cursor_obj.queries if "UPDATE" in q]
    assert len(update_queries) > 0
    assert "AND organization_id = %s" in update_queries[0]
    
    # 2. Scoped rejection
    agent_enrollment_service.reject_request(
        fake_conn,
        request_id="req-123",
        reviewed_by="admin-user",
        review_reason="Rejected",
        organization_id="org-a",
    )
    update_queries = [q for q in fake_conn.cursor_obj.queries if "UPDATE" in q]
    assert len(update_queries) > 1
    assert "AND organization_id = %s" in update_queries[1]
    
    # 3. Scoped revocation
    agent_enrollment_service.revoke_request(
        fake_conn,
        agent_id="agent-123",
        reviewed_by="admin-user",
        review_reason="Revoked",
        organization_id="org-a",
    )
    update_queries = [q for q in fake_conn.cursor_obj.queries if "UPDATE" in q]
    assert len(update_queries) > 2
    assert "AND organization_id = %s" in update_queries[2]


# --- 4. Test Scoped Destructive Operational Data Reset ---

def test_system_service_scoped_reset(monkeypatch):
    fake_conn = FakeConnection()
    
    # Mock _table_exists and _table_count to simulate tables containing data
    monkeypatch.setattr(system_service, "_table_exists", lambda cursor, table: True)
    monkeypatch.setattr(system_service, "_table_count", lambda cursor, table, org=None: 10)
    monkeypatch.setattr(system_service, "_clear_runtime_files", lambda: None)
    monkeypatch.setattr(system_service, "cleanup_old_backups", lambda: {"deleted": []})
    monkeypatch.setattr(system_service, "ensure_tables", lambda db_conn: None)
    monkeypatch.setattr(system_service, "log_action", lambda *args, **kwargs: None)
    
    # Track executed queries
    queries = []
    def record_execute(query, params=None):
        queries.append((" ".join(query.strip().split()), params or ()))
        
    monkeypatch.setattr(fake_conn.cursor_obj, "execute", record_execute)
    
    # Call scoped reset
    system_service.reset_operational_data(
        fake_conn,
        username="tenant-admin",
        organization_id="org-a",
        ip_address="192.168.1.5",
    )
    
    # Check that deletes are scoped to org-a
    delete_queries = [q for q, p in queries if "DELETE FROM" in q]
    assert len(delete_queries) > 0
    for q in delete_queries:
        assert "WHERE organization_id = %s" in q
