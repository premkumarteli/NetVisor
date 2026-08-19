"""
Regression and unit tests for certificate lifecycle management, cross-tenant scoping,
and role authorization (Requirement R1, R2, R3).
"""

from __future__ import annotations

import datetime
from typing import Optional
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.main import app
from backend.core.dependencies import (
    get_current_user,
    require_org_scoped_role,
)
from backend.db.session import get_db
from backend.services.ca import CertificateAuthority


# ==============================================================================
# In-Memory DB Mock
# ==============================================================================

class MockCursor:
    def __init__(self, db: MockDatabase):
        self.db = db
        self.last_results = []
        self._row_idx = 0
        self.executed_queries: list[tuple[str, tuple]] = []

    def execute(self, query: str, params: tuple = ()):
        self.executed_queries.append((query.strip(), params))
        norm = " ".join(query.strip().split()).upper()

        if "FROM AGENTS" in norm and "SELECT" in norm:
            rows = self.db.agents
            if "WHERE CERT_SERIAL IS NOT NULL AND ORGANIZATION_ID = %S" in norm:
                org_id = params[0]
                rows = [r for r in rows if r.get("cert_serial") and r.get("organization_id") == org_id]
            elif "WHERE ID = %S AND ORGANIZATION_ID = %S" in norm:
                agent_id, org_id = params[0], params[1]
                rows = [r for r in rows if r.get("id") == agent_id and r.get("organization_id") == org_id]
            elif "WHERE ID = %S" in norm:
                agent_id = params[0]
                rows = [r for r in rows if r.get("id") == agent_id]
            elif "WHERE CERT_SERIAL = %S" in norm:
                serial = params[0].upper()
                rows = [r for r in rows if (r.get("cert_serial") or "").upper() == serial]
            elif "WHERE CERT_SERIAL IS NOT NULL" in norm:
                rows = [r for r in rows if r.get("cert_serial")]

            sorted_rows = sorted(rows, key=lambda x: str(x.get("cert_issued_at") or ""), reverse=True)
            self.last_results = [
                {
                    "agent_id": r.get("id"),
                    "id": r.get("id"),
                    "hostname": r.get("hostname"),
                    "organization_id": r.get("organization_id"),
                    "cert_serial": r.get("cert_serial"),
                    "cert_fingerprint": r.get("cert_fingerprint"),
                    "cert_issued_at": r.get("cert_issued_at"),
                    "cert_expires_at": r.get("cert_expires_at"),
                    "cert_status": r.get("cert_status"),
                }
                for r in sorted_rows
            ]

        elif "FROM CERTIFICATE_REVOCATIONS" in norm and "SELECT" in norm:
            if "SELECT 1" in norm:
                serial = params[0].upper()
                match = [r for r in self.db.revocations if (r.get("serial_number") or "").upper() == serial]
                self.last_results = [{"1": 1}] if match else []
            elif "JOIN AGENTS" in norm and "WHERE A.ORGANIZATION_ID = %S" in norm:
                org_id = params[0]
                agent_map = {a["id"]: a for a in self.db.agents if a.get("organization_id") == org_id}
                filtered = [
                    {
                        "serial_number": r["serial_number"],
                        "agent_id": r["agent_id"],
                        "revoked_at": r["revoked_at"],
                        "revoked_by": r["revoked_by"],
                        "reason": r["reason"],
                    }
                    for r in self.db.revocations
                    if r.get("agent_id") in agent_map
                ]
                self.last_results = filtered
            else:
                self.last_results = [
                    {
                        "serial_number": r["serial_number"],
                        "agent_id": r["agent_id"],
                        "revoked_at": r["revoked_at"],
                        "revoked_by": r["revoked_by"],
                        "reason": r["reason"],
                    }
                    for r in self.db.revocations
                ]

        elif "UPDATE AGENTS SET CERT_STATUS = 'REVOKED'" in norm:
            agent_id, serial = params[0], params[1].upper()
            for a in self.db.agents:
                if a.get("id") == agent_id and (a.get("cert_serial") or "").upper() == serial:
                    a["cert_status"] = "revoked"

        elif "INSERT INTO CERTIFICATE_REVOCATIONS" in norm:
            serial, agent_id, revoked_by, reason = params[0].upper(), params[1], params[2], params[3]
            existing = [r for r in self.db.revocations if r.get("serial_number", "").upper() == serial]
            if existing:
                existing[0]["revoked_by"] = revoked_by
                existing[0]["reason"] = reason
                existing[0]["revoked_at"] = datetime.datetime.now(datetime.timezone.utc)
            else:
                self.db.revocations.append({
                    "serial_number": serial,
                    "agent_id": agent_id,
                    "revoked_by": revoked_by,
                    "reason": reason,
                    "revoked_at": datetime.datetime.now(datetime.timezone.utc),
                })

        self._row_idx = 0

    def fetchall(self):
        return list(self.last_results)

    def fetchone(self):
        if self.last_results and self._row_idx < len(self.last_results):
            row = self.last_results[self._row_idx]
            self._row_idx += 1
            return row
        return None

    def close(self):
        pass


class MockDatabase:
    def __init__(self):
        self.agents = []
        self.revocations = []
        self.committed = False

    def cursor(self, dictionary: bool = True):
        return MockCursor(self)

    def commit(self):
        self.committed = True

    def close(self):
        pass


@pytest.fixture
def mock_db():
    db = MockDatabase()
    now = datetime.datetime.now(datetime.timezone.utc)
    db.agents = [
        {
            "id": "agent-a-1",
            "organization_id": "org-A",
            "hostname": "host-a1.internal",
            "cert_serial": "A1001",
            "cert_fingerprint": "FP-A1",
            "cert_issued_at": now - datetime.timedelta(days=10),
            "cert_expires_at": now + datetime.timedelta(days=80),
            "cert_status": "valid",
        },
        {
            "id": "agent-a-2",
            "organization_id": "org-A",
            "hostname": "host-a2.internal",
            "cert_serial": "A1002",
            "cert_fingerprint": "FP-A2",
            "cert_issued_at": now - datetime.timedelta(days=5),
            "cert_expires_at": now + datetime.timedelta(days=85),
            "cert_status": "valid",
        },
        {
            "id": "agent-b-1",
            "organization_id": "org-B",
            "hostname": "host-b1.internal",
            "cert_serial": "B2001",
            "cert_fingerprint": "FP-B1",
            "cert_issued_at": now - datetime.timedelta(days=2),
            "cert_expires_at": now + datetime.timedelta(days=88),
            "cert_status": "valid",
        },
    ]
    db.revocations = [
        {
            "serial_number": "A1000",
            "agent_id": "agent-a-1",
            "revoked_at": now - datetime.timedelta(days=1),
            "revoked_by": "admin_a",
            "reason": "old_key",
        },
        {
            "serial_number": "B2000",
            "agent_id": "agent-b-1",
            "revoked_at": now - datetime.timedelta(days=3),
            "revoked_by": "admin_b",
            "reason": "compromised",
        },
    ]
    return db


# ==============================================================================
# Unit Tests for require_org_scoped_role
# ==============================================================================

def test_require_org_scoped_role_allows_authorized_role():
    dependency = require_org_scoped_role("org_admin", "super_admin")
    mock_user = {"user_id": "u1", "organization_id": "org-A", "role": "org_admin"}
    result = dependency(user=mock_user)
    assert result == mock_user


def test_require_org_scoped_role_rejects_unauthorized_role():
    dependency = require_org_scoped_role("org_admin", "super_admin")
    mock_user = {"user_id": "u2", "organization_id": "org-A", "role": "viewer"}
    with pytest.raises(HTTPException) as exc_info:
        dependency(user=mock_user)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Insufficient permissions"


def test_require_org_scoped_role_default_roles():
    dependency = require_org_scoped_role()
    mock_admin = {"user_id": "u1", "organization_id": "org-A", "role": "super_admin"}
    assert dependency(user=mock_admin) == mock_admin

    mock_unauth = {"user_id": "u2", "organization_id": "org-A", "role": "operator"}
    with pytest.raises(HTTPException) as exc_info:
        dependency(user=mock_unauth)
    assert exc_info.value.status_code == 403


# ==============================================================================
# Integration Tests: List Certificates Tenant Isolation
# ==============================================================================

def test_org_admin_only_sees_own_certificates(mock_db):
    """org_admin from Org A cannot list Org B's certificates."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.get("/api/v1/admin/certificates")
        assert resp.status_code == 200
        certs = resp.json()["certificates"]
        assert len(certs) == 2
        serials = [c["cert_serial"] for c in certs]
        assert "A1001" in serials
        assert "A1002" in serials
        assert "B2001" not in serials  # Org B cert NOT returned

    app.dependency_overrides.clear()


def test_org_b_admin_only_sees_org_b_certificates(mock_db):
    """org_admin from Org B only sees Org B's certificates."""
    user_b = {
        "user_id": "user-b",
        "organization_id": "org-B",
        "role": "org_admin",
        "username": "admin_b",
    }
    app.dependency_overrides[get_current_user] = lambda: user_b
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.get("/api/v1/admin/certificates")
        assert resp.status_code == 200
        certs = resp.json()["certificates"]
        assert len(certs) == 1
        assert certs[0]["cert_serial"] == "B2001"
        assert certs[0]["agent_id"] == "agent-b-1"

    app.dependency_overrides.clear()


def test_viewer_cannot_list_certificates(mock_db):
    """Non-admin user receives 403 Forbidden."""
    user_viewer = {
        "user_id": "viewer-1",
        "organization_id": "org-A",
        "role": "viewer",
        "username": "viewer",
    }
    app.dependency_overrides[get_current_user] = lambda: user_viewer
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.get("/api/v1/admin/certificates")
        assert resp.status_code == 403

    app.dependency_overrides.clear()


# ==============================================================================
# Integration Tests: CA Certificate Download
# ==============================================================================

def test_admin_can_download_ca_certificate():
    """Admin can download CA certificate PEM and fingerprint."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a

    with TestClient(app) as client:
        resp = client.get("/api/v1/admin/certificates/ca")
        assert resp.status_code == 200
        data = resp.json()
        assert "ca_cert_pem" in data
        assert "BEGIN CERTIFICATE" in data["ca_cert_pem"]
        assert "ca_fingerprint" in data

    app.dependency_overrides.clear()


def test_viewer_cannot_download_ca_certificate():
    """Non-admin receives 403 when trying to download CA cert."""
    user_viewer = {
        "user_id": "viewer-1",
        "organization_id": "org-A",
        "role": "viewer",
        "username": "viewer",
    }
    app.dependency_overrides[get_current_user] = lambda: user_viewer

    with TestClient(app) as client:
        resp = client.get("/api/v1/admin/certificates/ca")
        assert resp.status_code == 403

    app.dependency_overrides.clear()


# ==============================================================================
# Integration Tests: List Revocations Tenant Isolation
# ==============================================================================

def test_org_admin_only_sees_own_revocations(mock_db):
    """org_admin from Org A cannot list Org B's revocations."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.get("/api/v1/admin/certificates/revocations")
        assert resp.status_code == 200
        revs = resp.json()["revocations"]
        assert len(revs) == 1
        assert revs[0]["serial_number"] == "A1000"
        assert revs[0]["agent_id"] == "agent-a-1"

    app.dependency_overrides.clear()


def test_org_b_admin_only_sees_org_b_revocations(mock_db):
    """org_admin from Org B only sees Org B's revocations."""
    user_b = {
        "user_id": "user-b",
        "organization_id": "org-B",
        "role": "org_admin",
        "username": "admin_b",
    }
    app.dependency_overrides[get_current_user] = lambda: user_b
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.get("/api/v1/admin/certificates/revocations")
        assert resp.status_code == 200
        revs = resp.json()["revocations"]
        assert len(revs) == 1
        assert revs[0]["serial_number"] == "B2000"
        assert revs[0]["agent_id"] == "agent-b-1"

    app.dependency_overrides.clear()


# ==============================================================================
# Integration Tests: Revocation Tenant Scoping & Security
# ==============================================================================

def test_org_admin_cannot_revoke_cross_tenant_with_agent_id(mock_db):
    """org_admin from Org A cannot revoke Org B's certificate when agent_id is provided."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "B2001",
                "agent_id": "agent-b-1",
                "reason": "malicious_attempt",
            },
        )
        assert resp.status_code == 403
        assert "Agent does not belong to your organization" in resp.json()["detail"]

    app.dependency_overrides.clear()


def test_org_admin_cannot_revoke_cross_tenant_with_serial_only(mock_db):
    """org_admin from Org A cannot revoke Org B's certificate when only serial is provided."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "B2001",
                "reason": "malicious_serial_attempt",
            },
        )
        assert resp.status_code == 403
        assert "Certificate does not belong to your organization" in resp.json()["detail"]

    app.dependency_overrides.clear()


def test_org_admin_cannot_revoke_nonexistent_certificate(mock_db):
    """Attempting to revoke a non-existent serial returns 403."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "NONEXISTENT999",
                "reason": "test",
            },
        )
        assert resp.status_code == 403

    app.dependency_overrides.clear()


def test_org_admin_can_revoke_own_certificate_with_agent_id(mock_db):
    """org_admin from Org A can successfully revoke their own organization's certificate with agent_id."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "A1001",
                "agent_id": "agent-a-1",
                "reason": "key_rotation",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "revoked"
        assert data["serial_number"] == "A1001"

        # Verify DB state was updated
        agent_a1 = next(a for a in mock_db.agents if a["id"] == "agent-a-1")
        assert agent_a1["cert_status"] == "revoked"

        # Verify recorded in revocations
        rev = next(r for r in mock_db.revocations if r["serial_number"] == "A1001")
        assert rev["agent_id"] == "agent-a-1"
        assert rev["reason"] == "key_rotation"

    app.dependency_overrides.clear()


def test_org_admin_can_revoke_own_certificate_with_serial_only(mock_db):
    """org_admin from Org A can successfully revoke their own cert with only serial_number."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "A1002",
                "reason": "decommissioned",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "revoked"
        assert data["serial_number"] == "A1002"

        # Verify agent cert_status was updated
        agent_a2 = next(a for a in mock_db.agents if a["id"] == "agent-a-2")
        assert agent_a2["cert_status"] == "revoked"

    app.dependency_overrides.clear()


def test_revoke_already_revoked_returns_conflict(mock_db):
    """Attempting to revoke an already revoked certificate returns 409 Conflict."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        # A1000 is already in mock_db.revocations and belongs to agent-a-1 in Org A
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "A1000",
                "agent_id": "agent-a-1",
                "reason": "duplicate_attempt",
            },
        )
        assert resp.status_code == 409
        assert "Certificate already revoked" in resp.json()["detail"]

    app.dependency_overrides.clear()


# ==============================================================================
# Service Unit Test: CA list_revocations
# ==============================================================================

def test_ca_service_list_revocations_scoping(mock_db, tmp_path):
    ca = CertificateAuthority(tmp_path)
    # Filter by org-A
    revs_a = ca.list_revocations(mock_db, organization_id="org-A")
    assert len(revs_a) == 1
    assert revs_a[0]["serial_number"] == "A1000"

    # Filter by org-B
    revs_b = ca.list_revocations(mock_db, organization_id="org-B")
    assert len(revs_b) == 1
    assert revs_b[0]["serial_number"] == "B2000"

    # No filter (e.g. super admin)
    all_revs = ca.list_revocations(mock_db)
    assert len(all_revs) == 2


# ==============================================================================
# Adversarial Security & Edge Case Tests
# ==============================================================================

def test_cross_tenant_revocation_spoofed_agent_id_and_victim_serial(mock_db):
    """
    Adversarial test: An attacker in Org A provides their own valid agent_id
    ('agent-a-1') along with victim's certificate serial ('B2001' belonging to Org B).
    Must be rejected with 403 Forbidden.
    """
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "attacker_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "B2001",
                "agent_id": "agent-a-1",
                "reason": "spoofed_agent_cross_tenant_attack",
            },
        )
        assert resp.status_code == 403
        assert "Certificate does not belong to your organization" in resp.json()["detail"]

        # Ensure Org B cert was NOT revoked
        agent_b1 = next(a for a in mock_db.agents if a["id"] == "agent-b-1")
        assert agent_b1["cert_status"] == "valid"

    app.dependency_overrides.clear()


def test_org_admin_with_no_org_id_lists_empty_certificates(mock_db):
    """An org_admin with organization_id=None must see an empty list, not all certificates."""
    user_no_org = {
        "user_id": "user-none",
        "organization_id": None,
        "role": "org_admin",
        "username": "admin_no_org",
    }
    app.dependency_overrides[get_current_user] = lambda: user_no_org
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.get("/api/v1/admin/certificates")
        assert resp.status_code == 200
        assert resp.json()["certificates"] == []

    app.dependency_overrides.clear()


def test_org_admin_with_no_org_id_lists_empty_revocations(mock_db):
    """An org_admin with organization_id=None must see empty revocations."""
    user_no_org = {
        "user_id": "user-none",
        "organization_id": None,
        "role": "org_admin",
        "username": "admin_no_org",
    }
    app.dependency_overrides[get_current_user] = lambda: user_no_org
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.get("/api/v1/admin/certificates/revocations")
        assert resp.status_code == 200
        assert resp.json()["revocations"] == []

    app.dependency_overrides.clear()


def test_org_admin_with_no_org_id_cannot_revoke(mock_db):
    """An org_admin with organization_id=None cannot revoke certificates."""
    user_no_org = {
        "user_id": "user-none",
        "organization_id": None,
        "role": "org_admin",
        "username": "admin_no_org",
    }
    app.dependency_overrides[get_current_user] = lambda: user_no_org
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "A1001",
                "agent_id": "agent-a-1",
                "reason": "test",
            },
        )
        assert resp.status_code == 403

    app.dependency_overrides.clear()


def test_super_admin_without_org_id_sees_all_certificates_and_revocations(mock_db):
    """A super_admin without organization_id can see all fleet certificates and revocations."""
    super_admin = {
        "user_id": "root",
        "organization_id": None,
        "role": "super_admin",
        "username": "superadmin",
    }
    app.dependency_overrides[get_current_user] = lambda: super_admin
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        # Certs
        resp = client.get("/api/v1/admin/certificates")
        assert resp.status_code == 200
        certs = resp.json()["certificates"]
        assert len(certs) == 3
        serials = {c["cert_serial"] for c in certs}
        assert serials == {"A1001", "A1002", "B2001"}

        # Revocations
        resp_rev = client.get("/api/v1/admin/certificates/revocations")
        assert resp_rev.status_code == 200
        revs = resp_rev.json()["revocations"]
        assert len(revs) == 2
        rev_serials = {r["serial_number"] for r in revs}
        assert rev_serials == {"A1000", "B2000"}

    app.dependency_overrides.clear()


def test_multiple_historical_revocations_per_agent(mock_db, tmp_path):
    """Ensure multiple historical revocations for an agent are returned in list_revocations."""
    mock_db.revocations.append({
        "serial_number": "A0999",
        "agent_id": "agent-a-1",
        "revoked_at": datetime.datetime.now(datetime.timezone.utc),
        "revoked_by": "admin_a",
        "reason": "historical_rotation",
    })

    ca = CertificateAuthority(tmp_path)
    revs_a = ca.list_revocations(mock_db, organization_id="org-A")
    assert len(revs_a) == 2
    serials_a = {r["serial_number"] for r in revs_a}
    assert serials_a == {"A1000", "A0999"}

    # Org B still only sees B2000
    revs_b = ca.list_revocations(mock_db, organization_id="org-B")
    assert len(revs_b) == 1
    assert revs_b[0]["serial_number"] == "B2000"


def test_security_context_preserves_none_fields():
    """SecurityContext properly returns None instead of the string 'None' when values are None."""
    from backend.core.dependencies import SecurityContext
    ctx = SecurityContext(user_id="u1", organization_id=None, role="org_admin", email=None, username=None)
    assert ctx.organization_id is None
    assert ctx.get("organization_id") is None
    assert ctx.email is None
    assert ctx.username is None
    assert ctx.role == "org_admin"
    assert ctx.user_id == "u1"
    assert ctx.id == "u1"
    assert ctx["id"] == "u1"
    assert ctx["user_id"] == "u1"


def test_security_context_id_and_user_id_aliases():
    """SecurityContext resolves id and user_id interchangeably whether initialized with id or user_id."""
    from backend.core.dependencies import SecurityContext
    ctx1 = SecurityContext(id="user-123", role="viewer")
    assert ctx1.id == "user-123"
    assert ctx1.user_id == "user-123"
    assert ctx1["id"] == "user-123"
    assert ctx1["user_id"] == "user-123"
    assert ctx1.get("id") == "user-123"
    assert ctx1.get("user_id") == "user-123"

    ctx2 = SecurityContext(user_id="user-456", role="viewer")
    assert ctx2.id == "user-456"
    assert ctx2.user_id == "user-456"
    assert ctx2["id"] == "user-456"
    assert ctx2["user_id"] == "user-456"


def test_revoke_serial_case_normalization(mock_db):
    """Revoking with lowercase serial number succeeds and updates agent status."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "a1001",
                "reason": "case_test",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"
        assert resp.json()["serial_number"] == "A1001"

    app.dependency_overrides.clear()


def test_revoke_empty_or_whitespace_serial_returns_400(mock_db):
    """Revoking with empty or whitespace-only serial number returns HTTP 400 Bad Request."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        # Empty string
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "",
                "reason": "empty_test",
            },
        )
        assert resp.status_code == 400
        assert "Serial number cannot be empty" in resp.json()["detail"]

        # Whitespace-only string with agent_id
        resp_ws = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "agent_id": "agent-a-1",
                "serial_number": "   ",
                "reason": "whitespace_test",
            },
        )
        assert resp_ws.status_code == 400
        assert "Serial number cannot be empty" in resp_ws.json()["detail"]

    app.dependency_overrides.clear()


def test_org_admin_revoking_untracked_serial_with_valid_agent_id(mock_db):
    """
    When an admin in Org A provides a valid own agent_id ('agent-a-1')
    and a historical/untracked serial number ('HISTORICAL_999'), the revocation
    is recorded under agent-a-1 in Org A.
    """
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "HISTORICAL_999",
                "agent_id": "agent-a-1",
                "reason": "historical_key_revocation",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"
        assert resp.json()["serial_number"] == "HISTORICAL_999"

        rev = next(r for r in mock_db.revocations if r["serial_number"] == "HISTORICAL_999")
        assert rev["agent_id"] == "agent-a-1"

    app.dependency_overrides.clear()


def test_org_admin_revoking_cross_agent_same_org_resolves_correct_target(mock_db):
    """
    When an admin in Org A supplies agent_id='agent-a-1' and serial='A1002' (which belongs
    to agent-a-2 in the same organization Org A), the system must correctly resolve
    the target agent as 'agent-a-2', record the revocation under 'agent-a-2', and update
    agent-a-2's cert_status to 'revoked'.
    """
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "A1002",
                "agent_id": "agent-a-1",
                "reason": "reassigned_key",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"
        assert resp.json()["serial_number"] == "A1002"

        # Check agent-a-2 is marked revoked
        agent_a2 = next(a for a in mock_db.agents if a["id"] == "agent-a-2")
        assert agent_a2["cert_status"] == "revoked"

        # Check revocation record targets agent-a-2
        rev = next(r for r in mock_db.revocations if r["serial_number"] == "A1002")
        assert rev["agent_id"] == "agent-a-2"

    app.dependency_overrides.clear()


def test_super_admin_can_revoke_any_certificate_by_serial(mock_db):
    """A super_admin without organization_id can revoke any tenant's certificate by serial."""
    super_admin = {
        "user_id": "super-1",
        "organization_id": None,
        "role": "super_admin",
        "username": "superadmin",
    }
    app.dependency_overrides[get_current_user] = lambda: super_admin
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "B2001",
                "reason": "fleet_wide_super_admin_revocation",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

        agent_b1 = next(a for a in mock_db.agents if a["id"] == "agent-b-1")
        assert agent_b1["cert_status"] == "revoked"

    app.dependency_overrides.clear()


def test_super_admin_with_assigned_org_id_sees_all_fleet_certificates_and_revocations(mock_db):
    """A super_admin user record with an assigned org_id (e.g. from bootstrap) still has fleet-wide visibility."""
    super_admin_with_org = {
        "user_id": "super-org-1",
        "organization_id": "org-A",
        "role": "super_admin",
        "username": "superadmin_org_a",
    }
    app.dependency_overrides[get_current_user] = lambda: super_admin_with_org
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        # Should see all 3 certificates across org-A and org-B
        resp = client.get("/api/v1/admin/certificates")
        assert resp.status_code == 200
        certs = resp.json()["certificates"]
        assert len(certs) == 3
        serials = {c["cert_serial"] for c in certs}
        assert serials == {"A1001", "A1002", "B2001"}

        # Should see all revocations across org-A and org-B
        resp_rev = client.get("/api/v1/admin/certificates/revocations")
        assert resp_rev.status_code == 200
        revs = resp_rev.json()["revocations"]
        assert len(revs) == 2
        rev_serials = {r["serial_number"] for r in revs}
        assert rev_serials == {"A1000", "B2000"}

    app.dependency_overrides.clear()


def test_super_admin_with_assigned_org_id_can_revoke_other_org_certificate(mock_db):
    """A super_admin with an assigned org_id can revoke another organization's certificate with agent_id."""
    super_admin_with_org = {
        "user_id": "super-org-1",
        "organization_id": "org-A",
        "role": "super_admin",
        "username": "superadmin_org_a",
    }
    app.dependency_overrides[get_current_user] = lambda: super_admin_with_org
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "B2001",
                "agent_id": "agent-b-1",
                "reason": "cross_org_super_admin_action",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

        agent_b1 = next(a for a in mock_db.agents if a["id"] == "agent-b-1")
        assert agent_b1["cert_status"] == "revoked"

    app.dependency_overrides.clear()


def test_revoke_whitespace_padded_agent_id_trimmed_successfully(mock_db):
    """Providing agent_id with surrounding whitespace is safely trimmed and accepted."""
    user_a = {
        "user_id": "user-a",
        "organization_id": "org-A",
        "role": "org_admin",
        "username": "admin_a",
    }
    app.dependency_overrides[get_current_user] = lambda: user_a
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/admin/certificates/revoke",
            json={
                "serial_number": "A1001",
                "agent_id": "  agent-a-1  ",
                "reason": "trimmed_test",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

    app.dependency_overrides.clear()


def test_require_org_scoped_role_custom_role_sets():
    """Test require_org_scoped_role with specific custom role restrictions."""
    super_only = require_org_scoped_role("super_admin")
    super_user = {"user_id": "s1", "role": "super_admin"}
    org_user = {"user_id": "o1", "role": "org_admin"}
    assert super_only(user=super_user) == super_user
    with pytest.raises(HTTPException) as exc:
        super_only(user=org_user)
    assert exc.value.status_code == 403

    custom_dep = require_org_scoped_role("operator", "org_admin")
    op_user = {"user_id": "op1", "role": "operator"}
    viewer_user = {"user_id": "v1", "role": "viewer"}
    assert custom_dep(user=op_user) == op_user
    assert custom_dep(user=org_user) == org_user
    with pytest.raises(HTTPException) as exc2:
        custom_dep(user=viewer_user)
    assert exc2.value.status_code == 403



