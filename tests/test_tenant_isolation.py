"""
Tenant-isolation regression tests for the conditional tenant-scoping bypass.

Covers all 13 sites that previously skipped the org filter whenever
SINGLE_ORG_MODE was enabled (or when the caller had no org claim):

READ-guard sites:
   1. device_service.get_device_risk
   2. alert_service.get_risk_ranking
   3. agent_service._fetch_agents
   4. agent_service._fetch_device_counts
   5. agent_service._fetch_agent_devices (managed)
   6. agent_service._fetch_agent_devices (observed)
   7. agent_enrollment_service._fetch_request_by_agent
   8. agent_enrollment_service._fetch_request_by_id
   9. agent_enrollment_service.list_requests
  10. gateway_service.get_gateways_summary

WRITE-guard sites:
  11. agent_enrollment_service.approve_request
  12. agent_enrollment_service.reject_request
  13. agent_enrollment_service.revoke_request

Each test seeds two organizations ("org-a" / "org-b") with matching rows and
asserts that a caller scoped to org-a never observes or mutates org-b data,
regardless of the SINGLE_ORG_MODE flag value and regardless of a NULL org claim.

These tests require a local MySQL reachable with the credentials below and a
scratch database (network_security_test) that is created and dropped per run.
"""

import pytest

import mysql.connector

from backend.core.config import settings
from backend.services import (
    alert_service as alert_service_mod,
    agent_enrollment_service as enrollment_service_mod,
    agent_service as agent_service_mod,
    device_service as device_service_mod,
    gateway_service as gateway_service_mod,
)

import os

TEST_DB = "network_security_test"
DB_ARGS = dict(
    host=os.environ.get("NETVISOR_DB_HOST") or getattr(settings, "DB_HOST", "127.0.0.1"),
    user=os.environ.get("NETVISOR_DB_USER") or getattr(settings, "DB_USER", "root"),
    password=os.environ.get("NETVISOR_DB_PASSWORD") or getattr(settings, "DB_PASSWORD", "Prem@333"),
    port=int(os.environ.get("NETVISOR_DB_PORT") or getattr(settings, "DB_PORT", 3306)),
)

_FF = True
_NO = False
ALL_FLAGS = [_FF, _NO]

# ---------------------------------------------------------------- scratch DB

_TABLES = """
CREATE TABLE device_risks (
    device_id VARCHAR(50),
    organization_id VARCHAR(64),
    current_score FLOAT,
    risk_level VARCHAR(20),
    reasons TEXT
);

CREATE TABLE agents (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255),
    hostname VARCHAR(255),
    ip_address VARCHAR(50),
    os_family VARCHAR(50),
    version VARCHAR(50),
    inspection_enabled TINYINT DEFAULT 0,
    inspection_status VARCHAR(50),
    inspection_proxy_running TINYINT DEFAULT 0,
    inspection_ca_installed TINYINT DEFAULT 0,
    inspection_browsers_json TEXT,
    inspection_last_error TEXT,
    inspection_metrics_json TEXT,
    organization_id VARCHAR(64),
    last_seen DATETIME,
    cpu_usage FLOAT,
    ram_usage FLOAT,
    integrity_status VARCHAR(50),
    manifest_hash VARCHAR(64)
);

CREATE TABLE managed_devices (
    agent_id VARCHAR(100),
    device_ip VARCHAR(50),
    hostname VARCHAR(255),
    device_mac VARCHAR(50),
    os_family VARCHAR(50),
    organization_id VARCHAR(64),
    last_seen DATETIME
);

CREATE TABLE devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(100),
    ip VARCHAR(50),
    mac VARCHAR(20),
    hostname VARCHAR(255),
    vendor VARCHAR(255),
    device_type VARCHAR(50),
    os_family VARCHAR(50),
    is_online TINYINT DEFAULT 1,
    organization_id VARCHAR(64),
    last_seen DATETIME
);

CREATE TABLE agent_enrollment_requests (
    request_id CHAR(36) PRIMARY KEY,
    agent_id VARCHAR(100) NOT NULL,
    organization_id VARCHAR(64),
    hostname VARCHAR(100),
    device_ip VARCHAR(50),
    device_mac VARCHAR(50),
    os_family VARCHAR(50),
    agent_version VARCHAR(50),
    bootstrap_method VARCHAR(32),
    source_ip VARCHAR(50),
    machine_fingerprint CHAR(64),
    status VARCHAR(20),
    attempt_count INT DEFAULT 0,
    first_seen DATETIME,
    last_seen DATETIME,
    expires_at DATETIME,
    reviewed_by VARCHAR(100),
    reviewed_at DATETIME,
    review_reason TEXT,
    credential_issued_at DATETIME,
    UNIQUE KEY uq_agent_enrollment_agent (agent_id)
);

CREATE TABLE gateways (
    gateway_id VARCHAR(100) PRIMARY KEY,
    organization_id VARCHAR(64),
    hostname VARCHAR(255),
    capture_mode VARCHAR(50),
    cert_status VARCHAR(50),
    last_seen DATETIME
);

CREATE TABLE flow_ingest_batches (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_id VARCHAR(100),
    source_type VARCHAR(32),
    status VARCHAR(32),
    flow_count INT,
    attempt_count INT
);
"""

_SEED = """
INSERT INTO device_risks (device_id, organization_id, current_score, risk_level, reasons) VALUES
    ('10.0.0.10', 'org-a', 70.0, 'HIGH', 'evidence-A'),
    ('10.0.0.20', 'org-a', 55.0, 'MEDIUM', 'evidence-A2'),
    ('10.0.0.99', 'org-b', 90.0, 'CRITICAL', 'evidence-B');

INSERT INTO agents (id, name, hostname, ip_address, os_family, version,
                    organization_id, last_seen) VALUES
    ('AG-A', 'agent-a', 'host-a', '10.0.0.10', 'Windows', 'v3', 'org-a', UTC_TIMESTAMP()),
    ('AG-B', 'agent-b', 'host-b', '10.0.0.99', 'Linux', 'v3', 'org-b', UTC_TIMESTAMP());

INSERT INTO managed_devices (agent_id, device_ip, hostname, device_mac, os_family,
                             organization_id, last_seen) VALUES
    ('AG-A', '10.0.0.10', 'host-a', 'aa:bb:cc:dd:ee:01', 'Windows', 'org-a', UTC_TIMESTAMP()),
    ('AG-A', '10.0.1.1', 'host-a-other', 'aa:bb:cc:dd:ee:02', 'Linux', 'org-b', UTC_TIMESTAMP()),
    ('AG-B', '10.0.2.1', 'host-b', 'aa:bb:cc:dd:ee:03', 'Linux', 'org-b', UTC_TIMESTAMP());

INSERT INTO devices (agent_id, ip, mac, hostname, vendor, device_type, os_family,
                     is_online, organization_id, last_seen) VALUES
    ('AG-A', '10.0.0.20', 'aa:bb:cc:dd:ee:04', 'obs-a', 'N/A', 'Unknown', 'Windows', 1, 'org-a', UTC_TIMESTAMP()),
    ('AG-A', '10.0.1.2', 'aa:bb:cc:dd:ee:05', 'obs-a-other', 'N/A', 'Unknown', 'Linux', 1, 'org-b', UTC_TIMESTAMP()),
    ('AG-B', '10.0.2.2', 'aa:bb:cc:dd:ee:06', 'obs-b', 'N/A', 'Unknown', 'Linux', 1, 'org-b', UTC_TIMESTAMP());

INSERT INTO agent_enrollment_requests (
    request_id, agent_id, organization_id, hostname, device_ip, status,
    attempt_count, first_seen, last_seen) VALUES
    ('REQ-A', 'AG-A', 'org-a', 'host-a', '10.0.0.10', 'pending_review', 1, UTC_TIMESTAMP(), UTC_TIMESTAMP()),
    ('REQ-B', 'AG-B', 'org-b', 'host-b', '10.0.0.99', 'pending_review', 1, UTC_TIMESTAMP(), UTC_TIMESTAMP());

INSERT INTO gateways (gateway_id, organization_id, hostname, capture_mode, cert_status, last_seen) VALUES
    ('GW-A', 'org-a', 'gw-a', 'promiscuous', 'active', UTC_TIMESTAMP()),
    ('GW-B', 'org-b', 'gw-b', 'promiscuous', 'active', UTC_TIMESTAMP());
"""


def _connect(database: str | None = None):
    return mysql.connector.connect(**DB_ARGS, database=database, autocommit=False)


@pytest.fixture(scope="module", autouse=True)
def scratch_db():
    try:
        admin = _connect()
    except Exception as exc:
        pytest.skip(f"Scratch database unavailable: {exc}")
        return

    cur = admin.cursor()
    cur.execute(f"DROP DATABASE IF EXISTS {TEST_DB}")
    cur.execute(f"CREATE DATABASE {TEST_DB}")
    admin.commit()
    admin.close()

    conn = _connect(TEST_DB)
    cur = conn.cursor()
    for stmt in _TABLES.split(";"):
        if stmt.strip():
            cur.execute(stmt)
    for stmt in _SEED.split(";"):
        if stmt.strip():
            cur.execute(stmt)
    conn.commit()
    conn.close()
    yield
    try:
        admin = _connect()
        cur = admin.cursor()
        cur.execute(f"DROP DATABASE IF EXISTS {TEST_DB}")
        admin.commit()
        admin.close()
    except Exception:
        pass


@pytest.fixture()
def db_conn():
    conn = _connect(TEST_DB)
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def no_schema_checks(monkeypatch):
    monkeypatch.setattr(device_service_mod.device_service, "ensure_schema", lambda db_conn: None)
    monkeypatch.setattr(agent_service_mod.agent_service, "ensure_schema", lambda db_conn: None)
    monkeypatch.setattr(enrollment_service_mod.agent_enrollment_service, "ensure_schema", lambda db_conn: None)
    monkeypatch.setattr(gateway_service_mod.gateway_service, "ensure_table", lambda db_conn: None)


@pytest.fixture()
def org_flag(monkeypatch, request):
    monkeypatch.setattr(settings, "SINGLE_ORG_MODE", request.param)
    yield request.param


def _patch_flag(monkeypatch, value):
    monkeypatch.setattr(settings, "SINGLE_ORG_MODE", value)


# ------------------------------------------------------------ 1. device risk

@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_device_risk_org_a_never_sees_org_b(org_flag, db_conn):
    risk = device_service_mod.device_service.get_device_risk(db_conn, "10.0.0.99", "org-a")
    assert risk is None, f"org-a saw org-b risk row: {risk}"

    own = device_service_mod.device_service.get_device_risk(db_conn, "10.0.0.10", "org-a")
    assert own is not None and own["organization_id"] == "org-a"


def test_device_risk_null_org_is_no_access(db_conn, monkeypatch):
    _patch_flag(monkeypatch, False)
    risk = device_service_mod.device_service.get_device_risk(db_conn, "10.0.0.10", None)
    assert risk is None


# --------------------------------------------------------- 2. risk ranking

@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_risk_ranking_org_a_never_returns_org_b(org_flag, db_conn):
    rows = alert_service_mod.alert_service.get_risk_ranking(db_conn, "org-a", limit=10)
    assert rows, "org-a has seeded risk rows; none returned"
    org_b_devices = {"10.0.0.99"}
    assert all(r["device_id"] not in org_b_devices for r in rows), rows
    assert any(r["device_id"] == "10.0.0.10" for r in rows), rows


def test_risk_ranking_null_org_is_no_access(db_conn, monkeypatch):
    _patch_flag(monkeypatch, False)
    rows = alert_service_mod.alert_service.get_risk_ranking(db_conn, None, limit=10)
    assert rows == []


# ----------------------------------------------------- 3. agents list

@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_fetch_agents_org_a_never_returns_org_b(org_flag, db_conn):
    agents = agent_service_mod.agent_service._fetch_agents(db_conn, "org-a")
    ids = {a["agent_id"] for a in agents}
    assert "AG-B" not in ids, ids
    assert "AG-A" in ids


def test_fetch_agents_null_org_is_no_access(db_conn, monkeypatch):
    _patch_flag(monkeypatch, False)
    agents = agent_service_mod.agent_service._fetch_agents(db_conn, None)
    assert agents == []


# ----------------------------------------------------- 4. device counts

@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_fetch_device_counts_org_a_never_counts_org_b(org_flag, db_conn):
    counts = agent_service_mod.agent_service._fetch_device_counts(db_conn, "org-a")
    assert "AG-B" not in counts, counts
    assert counts.get("AG-A", 0) > 0


def test_fetch_device_counts_null_org_is_no_access(db_conn, monkeypatch):
    _patch_flag(monkeypatch, False)
    counts = agent_service_mod.agent_service._fetch_device_counts(db_conn, None)
    assert counts == {}


# ------------------------------------------------- 5/6. agent devices

@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_fetch_agent_devices_org_a_never_returns_org_b(org_flag, db_conn):
    devices = agent_service_mod.agent_service._fetch_agent_devices(db_conn, "AG-A", "org-a")
    ips = {d["ip"] for d in devices}
    assert "10.0.1.1" not in ips and "10.0.1.2" not in ips, ips
    assert "10.0.0.10" in ips and "10.0.0.20" in ips


def test_fetch_agent_devices_null_org_is_no_access(db_conn, monkeypatch):
    _patch_flag(monkeypatch, False)
    devices = agent_service_mod.agent_service._fetch_agent_devices(db_conn, "AG-A", None)
    assert devices == []


# --------------------------------------------- 7/8. enrollment fetch

@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_enrollment_fetch_by_agent_org_a_never_returns_org_b(org_flag, db_conn):
    row = enrollment_service_mod.agent_enrollment_service._fetch_request_by_agent(
        db_conn, agent_id="AG-B", organization_id="org-a"
    )
    assert row is None, row


@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_enrollment_fetch_by_id_org_a_never_returns_org_b(org_flag, db_conn):
    row = enrollment_service_mod.agent_enrollment_service._fetch_request_by_id(
        db_conn, request_id="REQ-B", organization_id="org-a"
    )
    assert row is None, row


def test_enrollment_fetch_null_org_is_no_access(db_conn, monkeypatch):
    _patch_flag(monkeypatch, False)
    svc = enrollment_service_mod.agent_enrollment_service
    assert svc._fetch_request_by_agent(db_conn, agent_id="AG-A", organization_id=None) is None
    assert svc._fetch_request_by_id(db_conn, request_id="REQ-A", organization_id=None) is None


# ------------------------------------------------- 9. list enrollments

@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_list_enrollment_org_a_never_returns_org_b(org_flag, db_conn):
    rows = enrollment_service_mod.agent_enrollment_service.list_requests(
        db_conn, organization_id="org-a"
    )
    assert rows and all(r["organization_id"] != "org-b" for r in rows), rows


def test_list_enrollment_null_org_is_no_access(db_conn, monkeypatch):
    _patch_flag(monkeypatch, False)
    rows = enrollment_service_mod.agent_enrollment_service.list_requests(db_conn, organization_id=None)
    assert rows == []


# ------------------------------------------------- 10. gateway summary

@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_gateway_summary_org_a_never_counts_org_b(org_flag, db_conn):
    summary = gateway_service_mod.gateway_service.get_gateways_summary(db_conn, "org-a")
    assert summary["total"] == 1, summary


def test_gateway_summary_null_org_is_no_access(db_conn, monkeypatch):
    _patch_flag(monkeypatch, False)
    summary = gateway_service_mod.gateway_service.get_gateways_summary(db_conn, None)
    assert summary["total"] == 0


# ---------------------------------------------- 11/12/13. write guards

@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_enrollment_approve_org_a_cannot_mutate_org_b(org_flag, db_conn):
    with pytest.raises(LookupError):
        enrollment_service_mod.agent_enrollment_service.approve_request(
            db_conn,
            request_id="REQ-B",
            reviewed_by="admin-a",
            review_reason="nope",
            organization_id="org-a",
        )


@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_enrollment_reject_org_a_cannot_mutate_org_b(org_flag, db_conn):
    with pytest.raises(LookupError):
        enrollment_service_mod.agent_enrollment_service.reject_request(
            db_conn,
            request_id="REQ-B",
            reviewed_by="admin-a",
            review_reason="nope",
            organization_id="org-a",
        )


@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_enrollment_revoke_org_a_cannot_mutate_org_b(org_flag, db_conn):
    with pytest.raises(LookupError):
        enrollment_service_mod.agent_enrollment_service.revoke_request(
            db_conn,
            agent_id="AG-B",
            reviewed_by="admin-a",
            review_reason="nope",
            organization_id="org-a",
        )


@pytest.mark.parametrize("org_flag", ALL_FLAGS, indirect=True)
def test_enrollment_write_null_org_never_mutates(org_flag, db_conn):
    with pytest.raises(LookupError):
        enrollment_service_mod.agent_enrollment_service.approve_request(
            db_conn,
            request_id="REQ-A",
            reviewed_by="admin",
            review_reason="no org",
            organization_id=None,
        )
    with pytest.raises(LookupError):
        enrollment_service_mod.agent_enrollment_service.reject_request(
            db_conn,
            request_id="REQ-A",
            reviewed_by="admin",
            review_reason="no org",
            organization_id=None,
        )
    with pytest.raises(LookupError):
        enrollment_service_mod.agent_enrollment_service.revoke_request(
            db_conn,
            agent_id="AG-A",
            reviewed_by="admin",
            review_reason="no org",
            organization_id=None,
        )