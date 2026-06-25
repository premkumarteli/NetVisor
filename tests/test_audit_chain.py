import hashlib
from datetime import datetime
from types import SimpleNamespace
import pytest
from app.services.audit_service import AuditService
from app.services.audit_chain_service import audit_chain_service
from app.api import audit_integrity as audit_api
from app.core.config import settings

class AuditLogDB:
    def __init__(self):
        self.rows = []
        self.last_id = 0

    def insert(self, organization_id, username, action, ip_address, resource, details, created_at):
        self.last_id += 1
        row = {
            "id": self.last_id,
            "organization_id": organization_id,
            "username": username,
            "action": action,
            "ip_address": ip_address,
            "resource": resource,
            "details": details,
            "created_at": created_at,
            "entry_hash": None,
            "chain_hash": None,
            "prev_id": None
        }
        self.rows.append(row)
        return self.last_id

    def update(self, row_id, entry_hash, chain_hash, prev_id):
        for row in self.rows:
            if row["id"] == row_id:
                row["entry_hash"] = entry_hash
                row["chain_hash"] = chain_hash
                row["prev_id"] = prev_id
                break

class FakeCursor:
    def __init__(self, db: AuditLogDB):
        self.db = db
        self.last_query = ""
        self.last_params = ()
        self.closed = False

    def execute(self, query, params=None):
        self.last_query = " ".join(query.strip().split())
        self.last_params = params or ()
        p = self.last_params
        if "UPDATE audit_logs SET entry_hash" in self.last_query:
            self.db.update(
                row_id=p[3],
                entry_hash=p[0],
                chain_hash=p[1],
                prev_id=p[2]
            )

    @property
    def lastrowid(self):
        if "INSERT INTO audit_logs" in self.last_query:
            p = self.last_params
            row_id = self.db.insert(
                organization_id=p[0],
                username=p[1],
                action=p[2],
                ip_address=p[3],
                resource=p[4],
                details=p[5],
                created_at=p[6]
            )
            return row_id
        return None

    def fetchone(self):
        if "SELECT id, chain_hash FROM audit_logs" in self.last_query:
            org_id = self.last_params[0]
            org_rows = [r for r in self.db.rows if r["organization_id"] == org_id]
            if org_rows:
                return org_rows[-1]
            return None
        if "SELECT chain_hash FROM audit_logs" in self.last_query:
            org_id = self.last_params[0]
            org_rows = [r for r in self.db.rows if r["organization_id"] == org_id and r["chain_hash"] is not None]
            if org_rows:
                return {"chain_hash": org_rows[-1]["chain_hash"]}
            return None
        if "SELECT COUNT(*)" in self.last_query:
            org_id = self.last_params[0]
            count = len([r for r in self.db.rows if r["organization_id"] == org_id])
            return {"count": count}
        return None

    def fetchall(self):
        if "SELECT id, organization_id" in self.last_query or "SELECT id, username" in self.last_query:
            org_id = self.last_params[0]
            limit = self.last_params[1] if len(self.last_params) > 1 else 1000
            org_rows = [r for r in self.db.rows if r["organization_id"] == org_id]
            return org_rows[:limit]
        return []

    def close(self):
        self.closed = True

class FakeConnection:
    def __init__(self, db: AuditLogDB):
        self.db = db
        self.committed = False
        self.rolled_back = False

    def cursor(self, dictionary=True):
        return FakeCursor(self.db)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass

def test_chain_genesis(monkeypatch):
    db = AuditLogDB()
    monkeypatch.setattr("app.services.audit_service.get_db_connection", lambda: FakeConnection(db))

    service = AuditService()
    service._log_audit_event("org-1", "user-1", "action-1", "127.0.0.1", "res-1", "details-1")

    assert len(db.rows) == 1
    row = db.rows[0]
    assert row["prev_id"] is None
    assert row["entry_hash"] is not None
    assert row["chain_hash"] is not None

    computed_input = f"{row['entry_hash']}|GENESIS"
    expected_chain = hashlib.sha256(computed_input.encode("utf-8")).hexdigest()
    assert row["chain_hash"] == expected_chain

def test_chain_links(monkeypatch):
    db = AuditLogDB()
    monkeypatch.setattr("app.services.audit_service.get_db_connection", lambda: FakeConnection(db))

    service = AuditService()
    service._log_audit_event("org-1", "user-1", "action-1", "127.0.0.1", "res-1", "details-1")
    service._log_audit_event("org-1", "user-1", "action-2", "127.0.0.1", "res-2", "details-2")

    assert len(db.rows) == 2
    row1 = db.rows[0]
    row2 = db.rows[1]

    assert row2["prev_id"] == row1["id"]
    computed_input = f"{row2['entry_hash']}|{row1['chain_hash']}"
    expected_chain = hashlib.sha256(computed_input.encode("utf-8")).hexdigest()
    assert row2["chain_hash"] == expected_chain

def test_verify_clean_chain(monkeypatch):
    db = AuditLogDB()
    monkeypatch.setattr("app.services.audit_service.get_db_connection", lambda: FakeConnection(db))

    service = AuditService()
    service._log_audit_event("org-1", "user-1", "action-1", "127.0.0.1", "res-1", "details-1")
    service._log_audit_event("org-1", "user-1", "action-2", "127.0.0.1", "res-2", "details-2")

    conn = FakeConnection(db)
    result = audit_chain_service.verify_chain(conn, "org-1")
    assert result["status"] == "ok"
    assert result["total_checked"] == 2
    assert result["first_broken_id"] is None
    assert result["chain_tip"] == db.rows[1]["chain_hash"]

def test_detect_tampered_entry(monkeypatch):
    db = AuditLogDB()
    monkeypatch.setattr("app.services.audit_service.get_db_connection", lambda: FakeConnection(db))

    service = AuditService()
    service._log_audit_event("org-1", "user-1", "action-1", "127.0.0.1", "res-1", "details-1")
    service._log_audit_event("org-1", "user-1", "action-2", "127.0.0.1", "res-2", "details-2")

    db.rows[0]["details"] = "tampered details"

    conn = FakeConnection(db)
    result = audit_chain_service.verify_chain(conn, "org-1")
    assert result["status"] == "broken"
    assert result["first_broken_id"] == db.rows[0]["id"]

def test_detect_deleted_row(monkeypatch):
    db = AuditLogDB()
    monkeypatch.setattr("app.services.audit_service.get_db_connection", lambda: FakeConnection(db))

    service = AuditService()
    service._log_audit_event("org-1", "user-1", "action-1", "127.0.0.1", "res-1", "details-1")
    service._log_audit_event("org-1", "user-1", "action-2", "127.0.0.1", "res-2", "details-2")
    service._log_audit_event("org-1", "user-1", "action-3", "127.0.0.1", "res-3", "details-3")

    db.rows.pop(1)

    conn = FakeConnection(db)
    result = audit_chain_service.verify_chain(conn, "org-1")
    assert result["status"] == "broken"
    assert result["first_broken_id"] == db.rows[1]["id"]

def test_partial_chain(monkeypatch):
    db = AuditLogDB()
    db.insert("org-1", "user-1", "action-1", "127.0.0.1", "res-1", "details-1", datetime.now())
    
    monkeypatch.setattr("app.services.audit_service.get_db_connection", lambda: FakeConnection(db))
    service = AuditService()
    service._log_audit_event("org-1", "user-1", "action-2", "127.0.0.1", "res-2", "details-2")

    conn = FakeConnection(db)
    result = audit_chain_service.verify_chain(conn, "org-1")
    assert result["status"] == "partial"
    assert result["total_checked"] == 1

def test_api_verify_endpoint():
    db = AuditLogDB()
    db.insert("org-1", "user-1", "action-1", "127.0.0.1", "res-1", "details-1", datetime.now())
    
    user = {"username": "admin", "role": "org_admin", "organization_id": "org-1"}
    request = SimpleNamespace()
    result = audit_api.verify_audit_chain(request, limit=1000, db=FakeConnection(db), user=user)
    assert result["status"] == "partial"
    assert result["total_checked"] == 0

def test_api_tip_endpoint():
    db = AuditLogDB()
    db.insert("org-1", "user-1", "action-1", "127.0.0.1", "res-1", "details-1", datetime.now())
    db.rows[0]["chain_hash"] = "fake_tip"
    
    user = {"username": "admin", "role": "org_admin", "organization_id": "org-1"}
    request = SimpleNamespace()
    result = audit_api.get_chain_tip(request, db=FakeConnection(db), user=user)
    assert result["chain_tip"] == "fake_tip"

def test_api_logs_endpoint():
    db = AuditLogDB()
    db.insert("org-1", "user-1", "action-1", "127.0.0.1", "res-1", "details-1", datetime.now())
    
    user = {"username": "admin", "role": "org_admin", "organization_id": "org-1"}
    request = SimpleNamespace()
    result = audit_api.get_audit_logs(request, limit=50, offset=0, db=FakeConnection(db), user=user)
    assert result["total"] == 1
    assert len(result["logs"]) == 1
    assert result["logs"][0]["action"] == "action-1"
