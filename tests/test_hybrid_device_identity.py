"""
Unit and Integration Tests for NetVisor Hybrid Device Identity Backend & Reconciliation.
Covers Requirements R3, R4, R5 from ORIGINAL_REQUEST.md and PROJECT.md.

Scenarios tested:
1. test_multi_nic_agent_registration_single_row
2. test_gateway_arp_secondary_mac_maps_to_canonical_row
3. test_agent_claims_preexisting_gateway_unmanaged_device
4. test_gateway_only_device_persists_null_uuid
5. test_uuid_conflict_handling_preserves_existing_uuid
6. test_stale_secondary_mac_excluded_or_pruned
7. test_gateway_backward_compatibility_payloads_unaltered
8. test_empty_or_invalid_mac_handling
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import pytest

from backend.db import session as db_session
from backend.services.device_service import device_service


class _HybridCursor:
    """
    Simulated MySQL cursor providing in-memory relational storage for
    devices, device_mac_addresses, device_identity_conflicts, and schema inspection.
    """

    def __init__(self, conn: "_HybridConnection", dictionary: bool = True):
        self.conn = conn
        self.dictionary = dictionary
        self._result: Optional[Any] = None
        self._results: List[Any] = []

    def execute(self, query: str, params: Optional[tuple | list] = None) -> None:
        normalized = " ".join(query.split())
        params = list(params) if params is not None else []

        # Information schema checks for runtime schema verification
        if "FROM information_schema.tables" in normalized:
            _, table_name = params
            self._result = {"count": 1 if table_name in self.conn.tables else 0}
            return

        if "FROM information_schema.columns" in normalized:
            _, table_name, column_name = params
            has_col = column_name in self.conn.columns.get(table_name, set())
            self._result = {"count": 1 if has_col else 0}
            return

        if "FROM information_schema.statistics" in normalized:
            _, table_name, index_name = params
            has_idx = index_name in self.conn.indexes.get(table_name, set())
            self._result = {"count": 1 if has_idx else 0}
            return

        # SELECT 1 FROM devices WHERE mac = ... (Pre-fix new device check)
        if normalized.startswith("SELECT 1 FROM devices WHERE mac = %s"):
            mac_val = params[0]
            org_id = params[1] if len(params) > 1 else None
            exists = any(
                d["mac"] == mac_val and (d.get("organization_id") == org_id or org_id is None)
                for d in self.conn.devices.values()
            )
            self._result = {"1": 1} if exists else None
            return

        # SELECT * / mac / device_uuid FROM devices WHERE mac = %s
        if "FROM devices WHERE mac = %s" in normalized:
            mac_val = params[0]
            row = next((d for d in self.conn.devices.values() if d["mac"] == mac_val), None)
            self._result = dict(row) if row else None
            return

        # SELECT * FROM devices WHERE device_uuid = %s
        if "FROM devices WHERE device_uuid = %s" in normalized:
            uuid_val = params[0]
            row = next((d for d in self.conn.devices.values() if d.get("device_uuid") == uuid_val), None)
            self._result = dict(row) if row else None
            return

        # SELECT COUNT(*) FROM devices
        if "SELECT COUNT(*) FROM devices" in normalized or "SELECT COUNT(*) as count FROM devices" in normalized:
            if "WHERE organization_id = %s" in normalized:
                org_id = params[0]
                count = sum(1 for d in self.conn.devices.values() if d.get("organization_id") == org_id)
            else:
                count = len(self.conn.devices)
            self._result = {"count": count}
            return

        # SELECT / COUNT(*) FROM device_mac_addresses
        if normalized.startswith("SELECT") and "FROM device_mac_addresses" in normalized:
            if "WHERE mac = %s" in normalized:
                mac_val = params[0]
                matching = [m for m in self.conn.device_mac_addresses if m["mac"] == mac_val]
                if "COUNT(*)" in normalized:
                    self._result = {"count": len(matching)}
                    self._results = []
                else:
                    self._result = dict(matching[0]) if matching else None
                    self._results = [dict(m) for m in matching]
                return
            if "WHERE device_uuid = %s" in normalized:
                uuid_val = params[0]
                matching = [m for m in self.conn.device_mac_addresses if m["device_uuid"] == uuid_val]
                if "COUNT(*)" in normalized:
                    self._result = {"count": len(matching)}
                    self._results = []
                else:
                    self._result = dict(matching[0]) if matching else None
                    self._results = [dict(m) for m in matching]
                return
            if "COUNT(*)" in normalized:
                self._result = {"count": len(self.conn.device_mac_addresses)}
                self._results = []
            else:
                self._result = dict(self.conn.device_mac_addresses[0]) if self.conn.device_mac_addresses else None
                self._results = [dict(m) for m in self.conn.device_mac_addresses]
            return

        # SELECT FROM device_identity_conflicts
        if normalized.startswith("SELECT") and "FROM device_identity_conflicts" in normalized:
            exist_uuid, in_uuid, conf_mac = params[2], params[3], params[4]
            match = next(
                (c for c in self.conn.device_identity_conflicts
                 if c["existing_device_uuid"] == exist_uuid
                 and c["incoming_device_uuid"] == in_uuid
                 and c["conflict_mac"] == conf_mac),
                None
            )
            self._result = dict(match) if match else None
            self._results = [dict(match)] if match else []
            return

        # INSERT INTO device_identity_conflicts
        if normalized.startswith("INSERT INTO device_identity_conflicts"):
            org_id, exist_uuid, in_uuid, conf_mac, f_seen, l_seen = params[0], params[1], params[2], params[3], params[4], params[5]
            new_conflict = {
                "id": len(self.conn.device_identity_conflicts) + 1,
                "organization_id": org_id,
                "existing_device_uuid": exist_uuid,
                "incoming_device_uuid": in_uuid,
                "conflict_mac": conf_mac,
                "consecutive_heartbeats": 1,
                "first_seen": f_seen,
                "last_seen": l_seen,
                "status": "pending",
            }
            self.conn.device_identity_conflicts.append(new_conflict)
            self._result = None
            return

        # UPDATE device_identity_conflicts
        if normalized.startswith("UPDATE device_identity_conflicts"):
            if "SET consecutive_heartbeats" in normalized:
                hb_count, seen_dt, conf_id = params[0], params[1], params[2]
                for c in self.conn.device_identity_conflicts:
                    if c["id"] == conf_id:
                        c["consecutive_heartbeats"] = hb_count
                        c["last_seen"] = seen_dt
            elif "SET status = 'resolved'" in normalized:
                seen_dt, exist_uuid, in_uuid = params[0], params[3], params[4]
                for c in self.conn.device_identity_conflicts:
                    if c["existing_device_uuid"] == exist_uuid and c["incoming_device_uuid"] == in_uuid:
                        c["status"] = "resolved"
                        c["last_seen"] = seen_dt
            self._result = None
            return

        # INSERT INTO devices ON DUPLICATE KEY UPDATE (Pre-fix standard insertion)
        if normalized.startswith("INSERT INTO devices"):
            ip, mac, hostname, vendor, device_type, os_family, org_id, agent_id, first_seen, last_seen = params[:10]
            device_uuid = params[10] if len(params) > 10 else None

            key = (mac, org_id)
            if key in self.conn.devices:
                dev = self.conn.devices[key]
                dev["ip"] = ip
                if hostname and hostname != "Unknown":
                    dev["hostname"] = hostname
                if vendor and vendor != "Unknown":
                    dev["vendor"] = vendor
                if device_type and device_type != "Unknown":
                    dev["device_type"] = device_type
                if os_family and os_family != "Unknown":
                    dev["os_family"] = os_family
                if agent_id:
                    dev["agent_id"] = agent_id
                if device_uuid:
                    dev["device_uuid"] = device_uuid
                dev["last_seen"] = last_seen
                dev["is_online"] = True
            else:
                self.conn.devices[key] = {
                    "id": len(self.conn.devices) + 1,
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname or "Unknown",
                    "vendor": vendor or "Unknown",
                    "device_type": device_type or "Unknown",
                    "os_family": os_family or "Unknown",
                    "is_online": True,
                    "organization_id": org_id,
                    "agent_id": agent_id,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "device_uuid": device_uuid,
                }
            self._result = None
            return

        # UPDATE devices
        if normalized.startswith("UPDATE devices"):
            if "WHERE id = %s" in normalized:
                row_id = params[-1]
                target_row = next((d for d in self.conn.devices.values() if d.get("id") == row_id), None)
                if target_row:
                    target_row["device_uuid"] = params[0]
                    target_row["ip"] = params[1]
                    if params[2]:
                        target_row["mac"] = params[2]
                    target_row["hostname"] = params[3]
                    target_row["vendor"] = params[5]
                    target_row["device_type"] = params[7]
                    target_row["os_family"] = params[9]
                    if params[11]:
                        target_row["agent_id"] = params[11]
                    target_row["last_seen"] = params[12]
                    target_row["is_online"] = True
            elif "WHERE device_uuid = %s" in normalized:
                target_uuid = params[-3] if "AND (organization_id" in normalized else params[-1]
                target_row = next((d for d in self.conn.devices.values() if d.get("device_uuid") == target_uuid), None)
                if target_row:
                    if "SET device_uuid = %s" in normalized:
                        target_row["device_uuid"] = params[0]
                        target_row["ip"] = params[1]
                        if params[2]:
                            target_row["mac"] = params[2]
                        target_row["hostname"] = params[3]
                        target_row["vendor"] = params[5]
                        target_row["device_type"] = params[7]
                        target_row["os_family"] = params[9]
                        if params[11]:
                            target_row["agent_id"] = params[11]
                        target_row["last_seen"] = params[12]
                        target_row["is_online"] = True
                    elif "SET ip = %s" in normalized:
                        target_row["ip"] = params[0]
                        if params[1]:
                            target_row["mac"] = params[1]
                        target_row["hostname"] = params[2]
                        target_row["vendor"] = params[4]
                        target_row["device_type"] = params[6]
                        target_row["os_family"] = params[8]
                        if params[10]:
                            target_row["agent_id"] = params[10]
                        target_row["last_seen"] = params[11]
                        target_row["is_online"] = True
                    elif "SET last_seen = GREATEST" in normalized:
                        target_row["last_seen"] = params[0]
                        target_row["is_online"] = True
            self._result = None
            return

        # INSERT INTO device_ip_history
        if normalized.startswith("INSERT INTO device_ip_history"):
            self._result = None
            return

        # INSERT INTO device_mac_addresses
        if normalized.startswith("INSERT INTO device_mac_addresses"):
            dev_uuid, mac_val, org_id, is_primary, last_seen = params[0], params[1], params[2], params[3], params[4]
            existing_mac = next(
                (m for m in self.conn.device_mac_addresses if m["mac"] == mac_val and (m.get("organization_id") == org_id or org_id is None)),
                None
            )
            if existing_mac:
                existing_mac["device_uuid"] = dev_uuid
                existing_mac["is_primary"] = bool(is_primary)
                existing_mac["last_seen"] = last_seen
                existing_mac["consecutive_misses"] = 0
            else:
                self.conn.device_mac_addresses.append({
                    "id": len(self.conn.device_mac_addresses) + 1,
                    "device_uuid": dev_uuid,
                    "mac": mac_val,
                    "organization_id": org_id,
                    "is_primary": bool(is_primary),
                    "last_seen": last_seen,
                    "consecutive_misses": 0,
                })
            self._result = None
            return

        # UPDATE device_mac_addresses
        if normalized.startswith("UPDATE device_mac_addresses"):
            if "consecutive_misses = consecutive_misses + 1" in normalized:
                dev_uuid = params[0]
                excluded = set(params[3:])
                for m in self.conn.device_mac_addresses:
                    if m["device_uuid"] == dev_uuid and m["mac"] not in excluded:
                        m["consecutive_misses"] = m.get("consecutive_misses", 0) + 1
            elif "SET device_uuid = %s WHERE device_uuid = %s" in normalized:
                new_uuid, old_uuid = params[0], params[1]
                for m in self.conn.device_mac_addresses:
                    if m["device_uuid"] == old_uuid:
                        m["device_uuid"] = new_uuid
            elif "SET last_seen = GREATEST" in normalized:
                seen_dt, dev_uuid, mac_val = params[0], params[1], params[2]
                for m in self.conn.device_mac_addresses:
                    if m["device_uuid"] == dev_uuid and m["mac"] == mac_val:
                        m["last_seen"] = seen_dt
            self._result = None
            return

        # DELETE FROM device_mac_addresses
        if normalized.startswith("DELETE FROM device_mac_addresses"):
            dev_uuid = params[0]
            self.conn.device_mac_addresses = [
                m for m in self.conn.device_mac_addresses
                if not (m["device_uuid"] == dev_uuid and m.get("consecutive_misses", 0) >= 30)
            ]
            self._result = None
            return

        # Fallback for other statements
        self._result = None

    def fetchone(self) -> Optional[dict]:
        return self._result

    def fetchall(self) -> List[dict]:
        return self._results or ([] if self._result is None else [self._result])

    def close(self) -> None:
        pass


class _HybridConnection:
    """Simulated database connection supporting transaction lifecycle and schema state."""

    def __init__(self):
        self.devices: Dict[tuple, dict] = {}
        self.device_mac_addresses: List[dict] = []
        self.device_identity_conflicts: List[dict] = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

        # Register baseline tables and columns matching pre-fix database init.sql
        self.tables: Set[str] = set(db_session.REQUIRED_RUNTIME_TABLES)
        self.columns: Dict[str, Set[str]] = {
            t: set(cols) for t, cols in db_session.REQUIRED_RUNTIME_COLUMNS.items()
        }
        self.indexes: Dict[str, Set[str]] = {
            t: set(idxs) for t, idxs in db_session.REQUIRED_RUNTIME_INDEXES.items()
        }

    def cursor(self, dictionary: bool = True) -> _HybridCursor:
        return _HybridCursor(self, dictionary=dictionary)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def hybrid_db(monkeypatch):
    """Provides an isolated in-memory DB connection and neutralizes live telemetry / audit dependencies."""
    conn = _HybridConnection()
    monkeypatch.setattr(db_session, "get_db_connection", lambda: conn)
    # Bypass schema caching during tests
    db_session.reset_schema_verification_cache()
    # Mark device_service schema as ready so ensure_schema uses our connection
    device_service._schema_ready = True
    return conn


def test_multi_nic_agent_registration_single_row(hybrid_db):
    """
    R3, R4: An agent host with multiple active NICs (e.g. eth0 and wlan0) reports
    device_uuid, primary_mac, and all_macs.
    The backend must create exactly ONE row in the devices table, with all interfaces
    registered in the device_mac_addresses table.
    """
    conn = hybrid_db
    primary_mac = "00:11:22:33:44:01"
    secondary_mac = "00:11:22:33:44:02"
    device_uuid = "c9bf9e57-1685-4c89-bafb-ff5af830be8a"
    all_macs = [primary_mac, secondary_mac]

    success = device_service.touch_device_seen(
        conn,
        ip="192.168.1.50",
        mac=primary_mac,
        primary_mac=primary_mac,
        all_macs=all_macs,
        device_uuid=device_uuid,
        hostname="MULTI-NIC-SERVER",
        agent_id="AGENT-MULTINIC-1",
        organization_id="default-org-id",
        create_if_missing=True,
    )
    assert success is True, "touch_device_seen must return True for valid multi-NIC registration"

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) FROM devices WHERE organization_id = %s", ("default-org-id",))
    count_row = cursor.fetchone()
    assert count_row["count"] == 1, (
        f"Multi-NIC agent registration must produce exactly 1 device row, found {count_row['count']}"
    )

    cursor.execute("SELECT device_uuid, mac, agent_id FROM devices WHERE device_uuid = %s", (device_uuid,))
    device_row = cursor.fetchone()
    assert device_row is not None, "Device row must be found by canonical device_uuid"
    assert device_row["device_uuid"] == device_uuid
    assert device_row["agent_id"] == "AGENT-MULTINIC-1"

    cursor.execute("SELECT * FROM device_mac_addresses WHERE device_uuid = %s", (device_uuid,))
    mac_rows = cursor.fetchall()
    assert len(mac_rows) == 2, (
        f"Expected exactly 2 entries in device_mac_addresses for multi-NIC agent, found {len(mac_rows)}"
    )
    stored_macs = {row["mac"] for row in mac_rows}
    assert stored_macs == {primary_mac, secondary_mac}


def test_gateway_arp_secondary_mac_maps_to_canonical_row(hybrid_db):
    """
    R4, R5: When a Gateway observes network traffic or ARP from an agent's secondary MAC,
    the telemetry must map to the existing canonical device row via device_mac_addresses.
    No duplicate device row may be created.
    """
    conn = hybrid_db
    canonical_uuid = "e8293774-325b-4c01-8b09-3cb9110b410f"
    primary_mac = "00:11:22:33:44:01"
    secondary_mac = "00:11:22:33:44:02"

    # Step 1: Agent registers with primary and secondary MAC
    device_service.touch_device_seen(
        conn,
        ip="192.168.1.50",
        mac=primary_mac,
        primary_mac=primary_mac,
        all_macs=[primary_mac, secondary_mac],
        device_uuid=canonical_uuid,
        hostname="DESKTOP-MULTI",
        agent_id="AGENT-CANONICAL",
        organization_id="default-org-id",
        create_if_missing=True,
    )

    # Step 2: Gateway discovers traffic from secondary_mac (ip 192.168.1.55) using unaltered gateway payload
    gateway_ingest_success = device_service.touch_device_seen(
        conn,
        ip="192.168.1.55",
        mac=secondary_mac,
        hostname="Unknown",
        organization_id="default-org-id",
        create_if_missing=True,
    )
    assert gateway_ingest_success is True

    # Exactly 1 row should exist in devices table (secondary MAC resolved to canonical row)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) FROM devices WHERE organization_id = %s", ("default-org-id",))
    count_row = cursor.fetchone()
    assert count_row["count"] == 1, (
        f"Gateway secondary MAC observation created a duplicate device row! Total rows: {count_row['count']}"
    )

    cursor.execute("SELECT device_uuid, agent_id FROM devices WHERE mac = %s", (primary_mac,))
    canonical_row = cursor.fetchone()
    assert canonical_row is not None
    assert canonical_row["device_uuid"] == canonical_uuid
    assert canonical_row["agent_id"] == "AGENT-CANONICAL"


def test_agent_claims_preexisting_gateway_unmanaged_device(hybrid_db):
    """
    R4, R5: When a Gateway first discovers an unmanaged device (device_uuid = NULL),
    and the NetVisor agent is subsequently installed on that host, the agent's registration
    must promote the existing device row in-place with its device_uuid rather than creating a duplicate.
    """
    conn = hybrid_db
    shared_mac = "00:11:22:33:44:99"
    promoted_uuid = "3a31c517-cbfd-46d2-a7d1-d246603a11f5"

    # Step 1: Gateway discovers unknown BYOD device
    device_service.touch_device_seen(
        conn,
        ip="192.168.1.99",
        mac=shared_mac,
        hostname="GATEWAY-DISCOVERED",
        vendor="Intel",
        organization_id="default-org-id",
        create_if_missing=True,
    )

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT mac, device_uuid FROM devices WHERE mac = %s", (shared_mac,))
    initial_row = cursor.fetchone()
    assert initial_row is not None
    assert initial_row.get("device_uuid") is None, "Gateway-only device must initially have NULL device_uuid"

    # Step 2: Agent installed on that machine registers with the same MAC
    device_service.touch_device_seen(
        conn,
        ip="192.168.1.99",
        mac=shared_mac,
        primary_mac=shared_mac,
        all_macs=[shared_mac],
        device_uuid=promoted_uuid,
        hostname="PROMOTED-WORKSTATION",
        agent_id="AGENT-PROMOTED",
        organization_id="default-org-id",
        create_if_missing=True,
    )

    # Step 3: Verify in-place promotion: exactly 1 device row, now bearing the agent's device_uuid
    cursor.execute("SELECT COUNT(*) FROM devices WHERE organization_id = %s", ("default-org-id",))
    count_row = cursor.fetchone()
    assert count_row["count"] == 1, (
        f"Agent claim created a duplicate device row instead of in-place promotion! Rows: {count_row['count']}"
    )

    cursor.execute("SELECT device_uuid, agent_id, hostname FROM devices WHERE mac = %s", (shared_mac,))
    promoted_row = cursor.fetchone()
    assert promoted_row["device_uuid"] == promoted_uuid, (
        f"Device row was not updated with promoted device_uuid, got: {promoted_row.get('device_uuid')}"
    )
    assert promoted_row["agent_id"] == "AGENT-PROMOTED"


def test_gateway_only_device_persists_null_uuid(hybrid_db):
    """
    R4, R5: Subnets without agents continue creating/updating device rows keyed on
    (mac, organization_id) with device_uuid remaining NULL.
    Runtime schema verification must confirm required hybrid tables and columns.
    """
    conn = hybrid_db
    gateway_mac = "00:22:33:44:55:66"

    # Runtime schema requirement: hybrid tables and columns must be registered
    assert "device_mac_addresses" in db_session.REQUIRED_RUNTIME_TABLES, (
        "device_mac_addresses table must be defined in REQUIRED_RUNTIME_TABLES"
    )
    assert "device_uuid" in db_session.REQUIRED_RUNTIME_COLUMNS.get("devices", set()), (
        "devices table must require device_uuid column in REQUIRED_RUNTIME_COLUMNS"
    )
    assert "uq_device_uuid_org" in db_session.REQUIRED_RUNTIME_INDEXES.get("devices", set()), (
        "devices table must require uq_device_uuid_org index in REQUIRED_RUNTIME_INDEXES"
    )

    # Gateway ingest with unaltered payload
    success = device_service.touch_device_seen(
        conn,
        ip="192.168.1.200",
        mac=gateway_mac,
        hostname="BYOD-PRINTER",
        vendor="HP",
        organization_id="default-org-id",
        create_if_missing=True,
    )
    assert success is True

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT mac, device_uuid FROM devices WHERE mac = %s", (gateway_mac,))
    row = cursor.fetchone()
    assert row is not None
    assert row.get("device_uuid") is None, (
        f"Gateway-only device must persist device_uuid as NULL, got {row.get('device_uuid')}"
    )

    # Confirm device_mac_addresses table is NOT populated for gateway-only devices
    cursor.execute("SELECT COUNT(*) FROM device_mac_addresses WHERE mac = %s", (gateway_mac,))
    mac_count = cursor.fetchone()
    assert mac_count["count"] == 0, "device_mac_addresses must not contain entries for gateway-only devices"


def test_uuid_conflict_handling_preserves_existing_uuid(hybrid_db):
    """
    R4: If an incoming device_uuid differs from the one stored against a row matched
    via MAC overlap (e.g. agent runtime wiped and regenerated new UUID), do NOT silently overwrite.
    Log conflict, keep existing device_uuid authoritative, and only accept the new UUID
    after a configurable threshold (e.g. 5 consecutive heartbeats) confirms re-provisioning.
    """
    conn = hybrid_db
    shared_mac = "00:11:22:33:44:aa"
    original_uuid = "11111111-1111-4111-8111-111111111111"
    rogue_uuid = "22222222-2222-4222-8222-222222222222"

    # Step 1: Enrolled agent with original UUID
    device_service.touch_device_seen(
        conn,
        ip="192.168.1.77",
        mac=shared_mac,
        primary_mac=shared_mac,
        all_macs=[shared_mac],
        device_uuid=original_uuid,
        hostname="AGENT-HOST",
        agent_id="AGENT-ORIG",
        organization_id="default-org-id",
        create_if_missing=True,
    )

    # Step 2: Conflicting UUID arrives on same MAC (Heartbeat 1)
    device_service.touch_device_seen(
        conn,
        ip="192.168.1.77",
        mac=shared_mac,
        primary_mac=shared_mac,
        all_macs=[shared_mac],
        device_uuid=rogue_uuid,
        hostname="AGENT-HOST",
        agent_id="AGENT-REINSTALLED",
        organization_id="default-org-id",
        create_if_missing=True,
    )

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT device_uuid FROM devices WHERE mac = %s", (shared_mac,))
    current_row = cursor.fetchone()
    assert current_row["device_uuid"] == original_uuid, (
        f"Incoming conflicting UUID silently overwrote authoritative UUID! Expected {original_uuid}, got {current_row['device_uuid']}"
    )

    # Step 3: Simulate consecutive heartbeats from new UUID to reach re-provisioning threshold (threshold = 5)
    for _ in range(4):
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.77",
            mac=shared_mac,
            primary_mac=shared_mac,
            all_macs=[shared_mac],
            device_uuid=rogue_uuid,
            hostname="AGENT-HOST",
            agent_id="AGENT-REINSTALLED",
            organization_id="default-org-id",
            create_if_missing=True,
        )

    # Step 4: After reaching threshold (5 consecutive heartbeats), re-provisioning event succeeds
    cursor.execute("SELECT device_uuid FROM devices WHERE mac = %s", (shared_mac,))
    final_row = cursor.fetchone()
    assert final_row["device_uuid"] == rogue_uuid, (
        f"Device failed to re-provision after reaching 5 consecutive heartbeats threshold. Current: {final_row['device_uuid']}"
    )


def test_stale_secondary_mac_excluded_or_pruned(hybrid_db):
    """
    R3: Multi-NIC Secondary MAC Staleness Policy (Active Pruning).
    Entries in device_mac_addresses not reported by their owning agent in N=30 consecutive
    heartbeats must be actively pruned from device_mac_addresses to prevent stale attachment.
    """
    conn = hybrid_db
    device_uuid = "44444444-4444-4444-8444-444444444444"
    primary_mac = "00:11:22:33:44:01"
    dongle_mac = "00:11:22:33:44:88"

    # Step 1: Agent registers with primary NIC and attached USB dongle
    device_service.touch_device_seen(
        conn,
        ip="192.168.1.10",
        mac=primary_mac,
        primary_mac=primary_mac,
        all_macs=[primary_mac, dongle_mac],
        device_uuid=device_uuid,
        organization_id="default-org-id",
        create_if_missing=True,
    )

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) FROM device_mac_addresses WHERE device_uuid = %s", (device_uuid,))
    assert cursor.fetchone()["count"] == 2, "Both interfaces should be initially registered"

    # Step 2: Dongle is unplugged. Agent sends 29 heartbeats with ONLY primary_mac
    for _ in range(29):
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.10",
            mac=primary_mac,
            primary_mac=primary_mac,
            all_macs=[primary_mac],
            device_uuid=device_uuid,
            organization_id="default-org-id",
            create_if_missing=True,
        )

    # At 29 misses, dongle_mac must still be retained (threshold not reached)
    cursor.execute("SELECT * FROM device_mac_addresses WHERE mac = %s", (dongle_mac,))
    row_29 = cursor.fetchone()
    assert row_29 is not None, "Secondary MAC was pruned prematurely before N=30 consecutive misses"

    # Step 3: 30th heartbeat without dongle_mac triggers active pruning
    device_service.touch_device_seen(
        conn,
        ip="192.168.1.10",
        mac=primary_mac,
        primary_mac=primary_mac,
        all_macs=[primary_mac],
        device_uuid=device_uuid,
        organization_id="default-org-id",
        create_if_missing=True,
    )

    # After 30 consecutive misses, dongle_mac must be actively pruned
    cursor.execute("SELECT * FROM device_mac_addresses WHERE mac = %s", (dongle_mac,))
    assert cursor.fetchone() is None, "Stale secondary MAC must be actively pruned after N=30 consecutive misses"


def test_gateway_backward_compatibility_payloads_unaltered(hybrid_db):
    """
    R4, R5: Gateway API and payload format remain 100% unaltered.
    Gateway batch ingestion succeeds against hybrid schema, verifying that
    gateway-only devices continue using (mac, organization_id) with device_uuid = NULL.
    """
    conn = hybrid_db
    gateway_mac = "06:c9:80:e9:52:ec"

    # Verify runtime schema enforces hybrid device identity guards
    assert "device_uuid" in db_session.REQUIRED_RUNTIME_COLUMNS.get("devices", set()), (
        "devices table must require device_uuid column in REQUIRED_RUNTIME_COLUMNS"
    )
    assert "uq_device_uuid_org" in db_session.REQUIRED_RUNTIME_INDEXES.get("devices", set()), (
        "devices table must require uq_device_uuid_org index in REQUIRED_RUNTIME_INDEXES"
    )

    # Gateway ingestion with standard unaltered gateway payload
    res = device_service.touch_device_seen(
        conn,
        ip="192.168.137.88",
        mac=gateway_mac,
        hostname="OPPO-Reno12-5G",
        device_type="Phone",
        os_family="Android",
        vendor="Oppo",
        organization_id="default-org-id",
        create_if_missing=True,
    )
    assert res is True

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT mac, device_uuid FROM devices WHERE mac = %s", (gateway_mac,))
    row = cursor.fetchone()
    assert row is not None
    assert row.get("device_uuid") is None, "Gateway payload must persist with device_uuid = NULL"


def test_empty_or_invalid_mac_handling(hybrid_db):
    """
    R2, R4: Adversarial input & boundary stress:
    When an agent provides empty, loopback, or invalid MAC strings in all_macs alongside a valid MAC,
    touch_device_seen must sanitize inputs, filter out invalid/loopback MACs, and associate only
    valid unicast MACs without crashing.
    """
    conn = hybrid_db
    valid_mac = "00:11:22:33:44:55"
    device_uuid = "55555555-5555-4555-8555-555555555555"

    dirty_macs = [
        "",
        "not-a-mac",
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
        "01:00:5e:00:00:01",
        valid_mac,
    ]

    success = device_service.touch_device_seen(
        conn,
        ip="192.168.1.10",
        mac="",
        primary_mac=valid_mac,
        all_macs=dirty_macs,
        device_uuid=device_uuid,
        hostname="EDGE-HOST",
        organization_id="default-org-id",
        create_if_missing=True,
    )
    assert success is True, "touch_device_seen must succeed with sanitized MAC inputs"

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM device_mac_addresses WHERE device_uuid = %s", (device_uuid,))
    entries = cursor.fetchall()
    assert len(entries) == 1, (
        f"Only valid MAC should be persisted in device_mac_addresses, found {len(entries)}"
    )
    assert entries[0]["mac"] == valid_mac
