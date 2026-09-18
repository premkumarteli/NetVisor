"""
Adversarial Stress and Reconciliation Test Suite for NetVisor Hybrid Device Identity.
Challenger Mandate Verification:
1. Dynamic multi-NIC roaming (WiFi <-> Ethernet IP/MAC handoff, rapid alternating primary MAC)
2. MAC address reassignment between devices after staleness threshold (N=30)
3. Rapid re-provisioning UUID conflicts (legitimate wipe vs. competing active claims)
4. Concurrent gateway ARP batches on secondary interfaces (multi-threaded race conditions)
5. Gateway-only device integrity (device_uuid = NULL persistence, no collisions)
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import pytest

from backend.db.session import get_db_connection, reset_schema_verification_cache
from backend.services.device_service import device_service

TEST_ORG_ID = "test-org-challenger"


@pytest.fixture(autouse=True)
def clean_challenger_db():
    """Ensures test org exists and cleans up tables before and after each test."""
    reset_schema_verification_cache()
    device_service._schema_ready = False

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM device_identity_conflicts WHERE organization_id = %s", (TEST_ORG_ID,))
        cursor.execute("DELETE FROM device_mac_addresses WHERE organization_id = %s", (TEST_ORG_ID,))
        cursor.execute("DELETE FROM devices WHERE organization_id = %s", (TEST_ORG_ID,))
        cursor.execute("DELETE FROM agent_enrollment_requests WHERE organization_id = %s", (TEST_ORG_ID,))
        cursor.execute(
            """
            INSERT INTO organizations (id, name, status)
            VALUES (%s, 'Challenger Test Org', 'active')
            ON DUPLICATE KEY UPDATE name = VALUES(name)
            """,
            (TEST_ORG_ID,),
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    yield

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM device_identity_conflicts WHERE organization_id = %s", (TEST_ORG_ID,))
        cursor.execute("DELETE FROM device_mac_addresses WHERE organization_id = %s", (TEST_ORG_ID,))
        cursor.execute("DELETE FROM devices WHERE organization_id = %s", (TEST_ORG_ID,))
        cursor.execute("DELETE FROM agent_enrollment_requests WHERE organization_id = %s", (TEST_ORG_ID,))
        cursor.execute("DELETE FROM organizations WHERE id = %s", (TEST_ORG_ID,))
        conn.commit()
    finally:
        cursor.close()
        conn.close()


# ============================================================================
# 1. DYNAMIC MULTI-NIC ROAMING STRESS
# ============================================================================

def test_dynamic_multi_nic_roaming_rapid_flip_flop():
    """
    Stress test: Agent device roams between Ethernet and WiFi 50 times,
    alternating primary_mac and IP, while gateway observes traffic on secondary interface.
    Verifies exactly 1 canonical device row persists with no duplicate entries.
    """
    conn = get_db_connection()
    try:
        device_uuid = "11111111-aaaa-4111-8111-111111111111"
        eth_mac = "00:11:22:33:44:01"
        wifi_mac = "00:11:22:33:44:02"
        eth_ip = "192.168.1.100"
        wifi_ip = "192.168.1.200"

        # 50 cycles of rapid roaming
        for cycle in range(50):
            if cycle % 2 == 0:
                # Active on Ethernet
                curr_prim = eth_mac
                curr_ip = eth_ip
                sec_mac = wifi_mac
            else:
                # Roamed to WiFi
                curr_prim = wifi_mac
                curr_ip = wifi_ip
                sec_mac = eth_mac

            # Agent heartbeat with both NICs
            res = device_service.touch_device_seen(
                conn,
                ip=curr_ip,
                mac=curr_prim,
                primary_mac=curr_prim,
                all_macs=[eth_mac, wifi_mac],
                device_uuid=device_uuid,
                hostname="ROAMING-LAPTOP",
                agent_id="AGENT-ROAM-01",
                organization_id=TEST_ORG_ID,
                create_if_missing=True,
            )
            assert res is True, f"Heartbeat failed on cycle {cycle}"
            conn.commit()

            # Gateway observes ARP telemetry on the secondary interface
            res_gw = device_service.touch_device_seen(
                conn,
                ip="192.168.1.250",
                mac=sec_mac,
                organization_id=TEST_ORG_ID,
                create_if_missing=True,
            )
            assert res_gw is True, f"Gateway observation failed on cycle {cycle}"
            conn.commit()

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS count FROM devices WHERE organization_id = %s", (TEST_ORG_ID,))
        dev_count = cursor.fetchone()["count"]
        assert dev_count == 1, f"Expected exactly 1 device row after roaming, found {dev_count}"

        cursor.execute("SELECT * FROM devices WHERE organization_id = %s", (TEST_ORG_ID,))
        dev_row = cursor.fetchone()
        assert dev_row["device_uuid"] == device_uuid
        assert dev_row["agent_id"] == "AGENT-ROAM-01"

        cursor.execute("SELECT * FROM device_mac_addresses WHERE organization_id = %s", (TEST_ORG_ID,))
        mac_rows = cursor.fetchall()
        assert len(mac_rows) == 2, f"Expected 2 MAC entries, found {len(mac_rows)}"
        mac_set = {r["mac"] for r in mac_rows}
        assert mac_set == {eth_mac, wifi_mac}
        for r in mac_rows:
            assert r["consecutive_misses"] == 0
        cursor.close()
    finally:
        conn.close()


# ============================================================================
# 2. MAC REASSIGNMENT AFTER STALENESS THRESHOLD (N=30)
# ============================================================================

def test_mac_reassignment_between_devices_after_staleness():
    """
    Stress test:
    - Device A has primary NIC A and removable USB NIC R.
    - Device A unplugs USB NIC R.
    - Heartbeats 1-29: Gateway ARP on NIC R still maps to Device A.
    - Heartbeat 30: NIC R is actively pruned.
    - Gateway ARP on NIC R now creates unmanaged row (device_uuid = NULL).
    - Device B plugs in USB NIC R as its secondary NIC.
    - Gateway ARP on NIC R now maps to Device B.
    - Both Device A and Device B remain distinct with zero UUID/MAC collisions.
    """
    conn = get_db_connection()
    try:
        uuid_a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        uuid_b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        mac_a = "00:aa:aa:aa:aa:01"
        mac_b = "00:bb:bb:bb:bb:01"
        mac_shared = "00:99:99:99:99:99"

        # 1. Device A registers with primary NIC A and shared USB NIC R
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.10",
            mac=mac_a,
            primary_mac=mac_a,
            all_macs=[mac_a, mac_shared],
            device_uuid=uuid_a,
            hostname="DEVICE-A",
            agent_id="AGENT-A",
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()

        # 2. USB NIC R is unplugged from Device A. Device A sends 29 heartbeats without it.
        for _ in range(29):
            device_service.touch_device_seen(
                conn,
                ip="192.168.1.10",
                mac=mac_a,
                primary_mac=mac_a,
                all_macs=[mac_a],
                device_uuid=uuid_a,
                hostname="DEVICE-A",
                agent_id="AGENT-A",
                organization_id=TEST_ORG_ID,
                create_if_missing=True,
            )
            conn.commit()

        # At miss 29: Gateway ARP on mac_shared must STILL map to Device A
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT consecutive_misses FROM device_mac_addresses WHERE mac = %s AND organization_id = %s",
            (mac_shared, TEST_ORG_ID),
        )
        mac_entry = cursor.fetchone()
        assert mac_entry is not None, "Shared MAC should still exist at 29 misses"
        assert mac_entry["consecutive_misses"] == 29

        device_service.touch_device_seen(
            conn,
            ip="192.168.1.88",
            mac=mac_shared,
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()
        # Verify no unmanaged device was created for mac_shared
        cursor.execute("SELECT COUNT(*) AS count FROM devices WHERE mac = %s AND organization_id = %s", (mac_shared, TEST_ORG_ID))
        assert cursor.fetchone()["count"] == 0, "Telemetry should have mapped to Device A, not created new row"

        # 3. 30th heartbeat from Device A triggers active pruning
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.10",
            mac=mac_a,
            primary_mac=mac_a,
            all_macs=[mac_a],
            device_uuid=uuid_a,
            hostname="DEVICE-A",
            agent_id="AGENT-A",
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()

        # Verify mac_shared is pruned from device_mac_addresses
        cursor.execute("SELECT * FROM device_mac_addresses WHERE mac = %s AND organization_id = %s", (mac_shared, TEST_ORG_ID))
        assert cursor.fetchone() is None, "Stale MAC must be pruned after 30 misses"

        # 4. Gateway ARP on mac_shared now creates an unmanaged row with device_uuid = NULL
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.88",
            mac=mac_shared,
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()
        cursor.execute("SELECT * FROM devices WHERE mac = %s AND organization_id = %s", (mac_shared, TEST_ORG_ID))
        unmanaged_row = cursor.fetchone()
        assert unmanaged_row is not None
        assert unmanaged_row["device_uuid"] is None

        # 5. Device B plugs in USB NIC R and claims it as secondary interface
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.20",
            mac=mac_b,
            primary_mac=mac_b,
            all_macs=[mac_b, mac_shared],
            device_uuid=uuid_b,
            hostname="DEVICE-B",
            agent_id="AGENT-B",
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()

        # In device_mac_addresses, mac_shared should now be bound to uuid_b
        cursor.execute("SELECT * FROM device_mac_addresses WHERE mac = %s AND organization_id = %s", (mac_shared, TEST_ORG_ID))
        shared_entry = cursor.fetchone()
        assert shared_entry is not None
        assert shared_entry["device_uuid"] == uuid_b
        assert shared_entry["consecutive_misses"] == 0

        # Gateway ARP on mac_shared now maps to Device B
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.88",
            mac=mac_shared,
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()

        # Both Device A and Device B must exist with their respective UUIDs
        cursor.execute("SELECT device_uuid FROM devices WHERE device_uuid = %s AND organization_id = %s", (uuid_a, TEST_ORG_ID))
        assert cursor.fetchone() is not None
        cursor.execute("SELECT device_uuid FROM devices WHERE device_uuid = %s AND organization_id = %s", (uuid_b, TEST_ORG_ID))
        assert cursor.fetchone() is not None
        cursor.close()
    finally:
        conn.close()


# ============================================================================
# 3. RAPID RE-PROVISIONING & COMPETING HEARTBEATS CONFLICTS
# ============================================================================

def test_legitimate_reprovisioning_after_agent_wipe():
    """
    R4: When an agent is wiped, generates a new UUID, and old UUID never heartbeats again,
    5 consecutive heartbeats from new UUID successfully re-provisions the canonical row.
    """
    conn = get_db_connection()
    try:
        shared_mac = "00:22:33:44:55:66"
        old_uuid = "11111111-2222-3333-4444-555555555555"
        new_uuid = "99999999-8888-7777-6666-555555555555"

        # Initial device registration
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.15",
            mac=shared_mac,
            primary_mac=shared_mac,
            all_macs=[shared_mac],
            device_uuid=old_uuid,
            hostname="HOST-ORIG",
            agent_id="AGENT-ORIG",
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()

        # Heartbeats 1 through 4 from new_uuid: row should keep old_uuid
        for hb in range(1, 5):
            device_service.touch_device_seen(
                conn,
                ip="192.168.1.15",
                mac=shared_mac,
                primary_mac=shared_mac,
                all_macs=[shared_mac],
                device_uuid=new_uuid,
                hostname="HOST-WIPED",
                agent_id="AGENT-NEW",
                organization_id=TEST_ORG_ID,
                create_if_missing=True,
            )
            conn.commit()

            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT device_uuid FROM devices WHERE mac = %s AND organization_id = %s", (shared_mac, TEST_ORG_ID))
            assert cursor.fetchone()["device_uuid"] == old_uuid, f"Overwrote prematurely at hb {hb}"
            cursor.close()

        # 5th heartbeat: re-provisioning threshold reached
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.15",
            mac=shared_mac,
            primary_mac=shared_mac,
            all_macs=[shared_mac],
            device_uuid=new_uuid,
            hostname="HOST-WIPED",
            agent_id="AGENT-NEW",
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT device_uuid FROM devices WHERE mac = %s AND organization_id = %s", (shared_mac, TEST_ORG_ID))
        assert cursor.fetchone()["device_uuid"] == new_uuid, "Failed to re-provision after 5 heartbeats"

        cursor.execute("SELECT status FROM device_identity_conflicts WHERE conflict_mac = %s AND organization_id = %s", (shared_mac, TEST_ORG_ID))
        conflict = cursor.fetchone()
        assert conflict is not None and conflict["status"] == "resolved"
        cursor.close()
    finally:
        conn.close()


def test_competing_active_claims_prevent_reprovisioning():
    """
    Adversarial Challenge: R4 states re-provisioning is only valid
    'with no competing claim from the old UUID'.
    If an attacker or rogue UUID sends heartbeats while the legitimate old UUID
    is also actively heartbeating, the conflict counter must NOT accumulate to 5
    and hijack the device.
    """
    conn = get_db_connection()
    try:
        shared_mac = "00:77:88:99:aa:bb"
        legit_uuid = "11111111-1111-4111-8111-111111111111"
        rogue_uuid = "66666666-6666-4666-8666-666666666666"

        # Legitimate agent registers
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.50",
            mac=shared_mac,
            primary_mac=shared_mac,
            all_macs=[shared_mac],
            device_uuid=legit_uuid,
            hostname="LEGIT-HOST",
            agent_id="AGENT-LEGIT",
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()

        # Interleave heartbeats: rogue sends 1, then legit sends 1, for 5 rounds
        for round_idx in range(5):
            # Rogue sends heartbeat claiming the MAC
            device_service.touch_device_seen(
                conn,
                ip="192.168.1.50",
                mac=shared_mac,
                primary_mac=shared_mac,
                all_macs=[shared_mac],
                device_uuid=rogue_uuid,
                hostname="ROGUE-HOST",
                agent_id="AGENT-ROGUE",
                organization_id=TEST_ORG_ID,
                create_if_missing=True,
            )
            conn.commit()

            # Legitimate agent immediately heartbeats (asserting active claim)
            device_service.touch_device_seen(
                conn,
                ip="192.168.1.50",
                mac=shared_mac,
                primary_mac=shared_mac,
                all_macs=[shared_mac],
                device_uuid=legit_uuid,
                hostname="LEGIT-HOST",
                agent_id="AGENT-LEGIT",
                organization_id=TEST_ORG_ID,
                create_if_missing=True,
            )
            conn.commit()

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT device_uuid FROM devices WHERE mac = %s AND organization_id = %s", (shared_mac, TEST_ORG_ID))
        current_dev = cursor.fetchone()
        cursor.close()

        # CRITICAL ASSERTION: The legitimate UUID must NOT have been hijacked by the rogue UUID
        # while the legitimate agent is actively heartbeating!
        assert current_dev["device_uuid"] == legit_uuid, (
            f"VULNERABILITY DETECTED: Rogue UUID hijacked device despite competing active heartbeats from legitimate owner! Current: {current_dev['device_uuid']}"
        )
    finally:
        conn.close()


# ============================================================================
# 4. CONCURRENT GATEWAY ARP BATCHES ON SECONDARY INTERFACES
# ============================================================================

def test_concurrent_gateway_arp_batches_on_secondary_interfaces():
    """
    Stress test: Multi-threaded race condition challenge.
    10 threads concurrently send gateway ARP batches for secondary interfaces while
    agent heartbeats on primary interface.
    Verifies no deadlocks, no duplicate device rows, and telemetry mapped properly.
    """
    device_uuid = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    primary_mac = "00:cc:cc:cc:cc:01"
    sec_mac_1 = "00:cc:cc:cc:cc:02"
    sec_mac_2 = "00:cc:cc:cc:cc:03"

    conn = get_db_connection()
    try:
        # Initial registration
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.30",
            mac=primary_mac,
            primary_mac=primary_mac,
            all_macs=[primary_mac, sec_mac_1, sec_mac_2],
            device_uuid=device_uuid,
            hostname="SERVER-NIC3",
            agent_id="AGENT-SRV",
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()
    finally:
        conn.close()

    def worker_task(thread_id: int):
        thread_conn = get_db_connection()
        try:
            for i in range(10):
                if thread_id % 3 == 0:
                    # Agent heartbeat
                    device_service.touch_device_seen(
                        thread_conn,
                        ip="192.168.1.30",
                        mac=primary_mac,
                        primary_mac=primary_mac,
                        all_macs=[primary_mac, sec_mac_1, sec_mac_2],
                        device_uuid=device_uuid,
                        organization_id=TEST_ORG_ID,
                        create_if_missing=True,
                    )
                elif thread_id % 3 == 1:
                    # Gateway ARP batch on sec_mac_1
                    device_service.touch_device_seen(
                        thread_conn,
                        ip="192.168.1.31",
                        mac=sec_mac_1,
                        organization_id=TEST_ORG_ID,
                        create_if_missing=True,
                    )
                else:
                    # Gateway ARP batch on sec_mac_2
                    device_service.touch_device_seen(
                        thread_conn,
                        ip="192.168.1.32",
                        mac=sec_mac_2,
                        organization_id=TEST_ORG_ID,
                        create_if_missing=True,
                    )
                thread_conn.commit()
            return True
        finally:
            thread_conn.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker_task, tid) for tid in range(8)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
        assert all(results)

    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS count FROM devices WHERE organization_id = %s", (TEST_ORG_ID,))
        total_devices = cursor.fetchone()["count"]
        assert total_devices == 1, f"Expected exactly 1 canonical device row, found {total_devices}"

        cursor.execute("SELECT * FROM devices WHERE organization_id = %s", (TEST_ORG_ID,))
        canonical = cursor.fetchone()
        assert canonical["device_uuid"] == device_uuid
        assert bool(canonical["is_online"]) is True

        cursor.execute("SELECT COUNT(*) AS count FROM device_mac_addresses WHERE device_uuid = %s AND organization_id = %s", (device_uuid, TEST_ORG_ID))
        total_macs = cursor.fetchone()["count"]
        assert total_macs == 3, f"Expected all 3 MACs bound in device_mac_addresses, found {total_macs}"
        cursor.close()
    finally:
        conn.close()


# ============================================================================
# 5. GATEWAY-ONLY DEVICE INTEGRITY & ISOLATION
# ============================================================================

def test_gateway_only_devices_persist_null_uuid_and_never_collide():
    """
    R4, R5: Verify gateway-only devices persist device_uuid = NULL,
    multiple unmanaged devices coexist with NULL UUIDs without unique constraint collision,
    and agent enrollments do not inadvertently attach or overwrite unmanaged devices.
    """
    conn = get_db_connection()
    try:
        # Seed 10 unmanaged gateway devices
        for i in range(10):
            gw_mac = f"02:00:00:00:00:{i:02x}"
            gw_ip = f"192.168.1.{100 + i}"
            device_service.touch_device_seen(
                conn,
                ip=gw_ip,
                mac=gw_mac,
                hostname=f"UNMANAGED-{i}",
                vendor="Generic Device",
                organization_id=TEST_ORG_ID,
                create_if_missing=True,
            )
        conn.commit()

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS count FROM devices WHERE organization_id = %s", (TEST_ORG_ID,))
        assert cursor.fetchone()["count"] == 10

        cursor.execute("SELECT COUNT(*) AS count FROM devices WHERE device_uuid IS NULL AND organization_id = %s", (TEST_ORG_ID,))
        assert cursor.fetchone()["count"] == 10, "All 10 gateway devices must have device_uuid = NULL"

        # Agent registers on a completely distinct MAC
        agent_uuid = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        agent_mac = "02:00:00:00:00:aa"
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.250",
            mac=agent_mac,
            primary_mac=agent_mac,
            all_macs=[agent_mac],
            device_uuid=agent_uuid,
            hostname="NEW-AGENT-HOST",
            agent_id="AGENT-FRESH",
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()

        cursor.execute("SELECT COUNT(*) AS count FROM devices WHERE organization_id = %s", (TEST_ORG_ID,))
        assert cursor.fetchone()["count"] == 11

        cursor.execute("SELECT COUNT(*) AS count FROM devices WHERE device_uuid IS NULL AND organization_id = %s", (TEST_ORG_ID,))
        assert cursor.fetchone()["count"] == 10, "Original 10 gateway devices must still have device_uuid = NULL"

        # Now agent registers claiming ONE existing gateway device (in-place promotion)
        claimed_mac = "02:00:00:00:00:05"
        promoted_uuid = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        device_service.touch_device_seen(
            conn,
            ip="192.168.1.105",
            mac=claimed_mac,
            primary_mac=claimed_mac,
            all_macs=[claimed_mac],
            device_uuid=promoted_uuid,
            hostname="PROMOTED-HOST",
            agent_id="AGENT-PROMOTED",
            organization_id=TEST_ORG_ID,
            create_if_missing=True,
        )
        conn.commit()

        cursor.execute("SELECT COUNT(*) AS count FROM devices WHERE organization_id = %s", (TEST_ORG_ID,))
        assert cursor.fetchone()["count"] == 11, "Claiming gateway device must update in-place without row duplication"

        cursor.execute("SELECT COUNT(*) AS count FROM devices WHERE device_uuid IS NULL AND organization_id = %s", (TEST_ORG_ID,))
        assert cursor.fetchone()["count"] == 9, "Exactly 9 gateway devices should remain unmanaged (device_uuid = NULL)"

        cursor.execute("SELECT * FROM devices WHERE mac = %s AND organization_id = %s", (claimed_mac, TEST_ORG_ID))
        promoted_row = cursor.fetchone()
        assert promoted_row["device_uuid"] == promoted_uuid
        assert promoted_row["agent_id"] == "AGENT-PROMOTED"
        cursor.close()
    finally:
        conn.close()
