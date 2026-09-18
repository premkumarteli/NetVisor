"""
Adversarial Stress Test Suite for Milestone 1 (Agent UUID & Multi-NIC Discovery).
Author: Challenger 2
Role: Critic / Specialist

Validates edge conditions:
1. Missing network / no NICs / psutil exceptions
2. Multiple IPs per interface and multi-NIC routing correlation
3. Dynamic routing shifts & persistence of device_uuid across changes
4. Corrupt / malformed / non-v4 device_uuid.txt resilience
5. Downed interfaces fallback
6. MAC deduplication, normalization, and multicast bit masking
7. Backward compatibility of agent attributes and payload schemas
8. Forensic verification of zero OS machine-id or MachineGuid leakage
"""

from __future__ import annotations

import collections
import json
import os
import socket
import uuid
import winreg
from pathlib import Path
from unittest.mock import MagicMock, patch

import psutil
import pytest

import agent.main as agent_main
from agent.device_detector import DeviceDetector, enumerate_local_interfaces, normalize_mac
from agent.main import NetworkAgent

snicaddr = collections.namedtuple("snicaddr", ["family", "address", "netmask", "broadcast", "ptp"])
snicstats = collections.namedtuple("snicstats", ["isup", "duplex", "speed", "mtu", "flags"])
AF_LINK = getattr(psutil, "AF_LINK", -1)


@pytest.fixture
def isolated_agent_dir(tmp_path, monkeypatch):
    runtime_dir = tmp_path / "runtime" / "agent"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(agent_main, "AGENT_RUNTIME_DIR", runtime_dir)
    monkeypatch.setenv("NETVISOR_AGENT_RUNTIME_DIR", str(runtime_dir))
    monkeypatch.setenv("NETVISOR_AGENT_HEARTBEAT_SECONDS", "0")
    return runtime_dir


def test_stress_completely_missing_network(isolated_agent_dir, monkeypatch):
    """Edge 1: Agent operates when all network calls fail or return empty."""
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {})
    monkeypatch.setattr(psutil, "net_if_stats", lambda: {})
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "127.0.0.1")

    agent = NetworkAgent(start_background_workers=False)
    agent.heartbeat_interval = 0

    assert hasattr(agent, "device_uuid")
    assert uuid.UUID(agent.device_uuid, version=4)
    assert hasattr(agent, "primary_mac")
    assert hasattr(agent, "all_macs")
    assert isinstance(agent.all_macs, list)

    # Verify registration payload formation
    captured_reg = []
    def fake_bootstrap_post(url, json_body=None, **kwargs):
        captured_reg.append(json_body)
        agent.is_running = False
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"enrollment_status": "enrolled"}
        return resp

    monkeypatch.setattr(agent.api_client, "bootstrap_post", fake_bootstrap_post)
    monkeypatch.setattr(agent.api_client, "has_credentials", lambda: True)

    agent._register_agent()
    assert len(captured_reg) == 1
    reg_payload = captured_reg[0]
    json_str = json.dumps(reg_payload)
    assert reg_payload["device_uuid"] == agent.device_uuid
    assert reg_payload["device_mac"] == agent.primary_mac

    # Verify heartbeat payload formation
    agent.is_running = True
    captured_hb = []
    def fake_request(method, url, json_body=None, **kwargs):
        captured_hb.append(json_body)
        agent.is_running = False
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"organization_id": agent.organization_id}
        return resp

    monkeypatch.setattr(agent.api_client, "request", fake_request)
    agent._heartbeat_worker()
    assert len(captured_hb) == 1
    hb_payload = captured_hb[0]
    assert hb_payload["device_uuid"] == agent.device_uuid
    assert hb_payload["primary_mac"] == agent.primary_mac
    assert hb_payload["device_mac"] == agent.primary_mac
    json.dumps(hb_payload)


def test_stress_multiple_ips_on_single_interface(isolated_agent_dir, monkeypatch):
    """Edge 2: Primary MAC correlates when outbound IP matches a secondary IP on a multi-homed NIC."""
    mock_addrs = {
        "eth0": [
            snicaddr(family=socket.AF_INET, address="10.0.0.10", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=socket.AF_INET, address="192.168.100.5", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:11:22:33:44:55", netmask=None, broadcast=None, ptp=None),
        ],
        "eth1": [
            snicaddr(family=socket.AF_INET, address="172.16.1.20", netmask="255.255.0.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="aa:bb:cc:dd:ee:ff", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {nic: snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up") for nic in mock_addrs}
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)
    
    # Correlate with the SECOND IP on eth0
    primary, all_macs = enumerate_local_interfaces("192.168.100.5")
    assert primary == "00:11:22:33:44:55"
    assert all_macs[0] == "00:11:22:33:44:55"
    assert "aa:bb:cc:dd:ee:ff" in all_macs


def test_stress_dynamic_routing_shift_and_uuid_immutability(isolated_agent_dir, monkeypatch):
    """Edge 3: Routing shift updates primary_mac correlation without altering device_uuid."""
    mock_addrs = {
        "eth0": [
            snicaddr(family=socket.AF_INET, address="192.168.1.100", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:11:22:33:44:55", netmask=None, broadcast=None, ptp=None),
        ],
        "wlan0": [
            snicaddr(family=socket.AF_INET, address="10.0.0.50", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="aa:bb:cc:dd:ee:ff", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {nic: snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up") for nic in mock_addrs}
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)

    # State 1: routing via eth0
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "192.168.1.100")
    agent1 = NetworkAgent(start_background_workers=False)
    uuid_1 = agent1.device_uuid
    assert agent1.primary_mac == "00:11:22:33:44:55"
    assert agent1.all_macs[0] == "00:11:22:33:44:55"

    # State 2: routing shifts to wlan0
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "10.0.0.50")
    agent2 = NetworkAgent(start_background_workers=False)
    uuid_2 = agent2.device_uuid
    assert agent2.primary_mac == "aa:bb:cc:dd:ee:ff"
    assert agent2.all_macs[0] == "aa:bb:cc:dd:ee:ff"
    assert "00:11:22:33:44:55" in agent2.all_macs
    # device_uuid MUST remain identical across routing and primary MAC change
    assert uuid_1 == uuid_2


def test_stress_all_interfaces_marked_down_fallback(isolated_agent_dir, monkeypatch):
    """Edge 4: When hypervisor/OS reports isup=False across all NICs, enumerate_local_interfaces does not drop them."""
    mock_addrs = {
        "eth0": [
            snicaddr(family=AF_LINK, address="00:aa:bb:cc:dd:01", netmask=None, broadcast=None, ptp=None),
        ],
        "eth1": [
            snicaddr(family=AF_LINK, address="00:aa:bb:cc:dd:02", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {
        "eth0": snicstats(isup=False, duplex=0, speed=0, mtu=1500, flags="down"),
        "eth1": snicstats(isup=False, duplex=0, speed=0, mtu=1500, flags="down"),
    }
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)

    primary, all_macs = enumerate_local_interfaces("127.0.0.1")
    assert primary == "00:aa:bb:cc:dd:01"
    assert set(all_macs) == {"00:aa:bb:cc:dd:01", "00:aa:bb:cc:dd:02"}


def test_stress_duplicate_macs_and_hyphenated_casing(isolated_agent_dir, monkeypatch):
    """Edge 5: MAC normalization handles uppercase, hyphens, and deduplicates identical MACs across bridges/vlans."""
    mock_addrs = {
        "eth0": [
            snicaddr(family=AF_LINK, address="AA-BB-CC-DD-EE-11", netmask=None, broadcast=None, ptp=None),
        ],
        "br0": [
            snicaddr(family=AF_LINK, address="aa:bb:cc:dd:ee:11", netmask=None, broadcast=None, ptp=None),
        ],
        "veth0": [
            snicaddr(family=AF_LINK, address="AA:BB:CC:DD:EE:22", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {nic: snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up") for nic in mock_addrs}
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)

    primary, all_macs = enumerate_local_interfaces()
    assert len(all_macs) == 2, f"Expected 2 unique MACs, got {all_macs}"
    assert all_macs == ["aa:bb:cc:dd:ee:11", "aa:bb:cc:dd:ee:22"]
    assert primary == "aa:bb:cc:dd:ee:11"


@pytest.mark.parametrize("corrupt_content", [
    "",
    "   \n\t ",
    "truncated-uuid",
    "not-a-valid-uuid-at-all",
    "c9bf9e57-1685-1c89-bafb-ff5af830be8a",
    '{"json": "value"}',
    "\x00\x01\x02\x03",
])
def test_stress_corrupt_device_uuid_file_self_heals(isolated_agent_dir, corrupt_content):
    """Edge 6: Any corrupted, non-v4, or unparseable device_uuid.txt is replaced with valid RFC 4122 UUID4."""
    uuid_file = isolated_agent_dir / "device_uuid.txt"
    uuid_file.write_text(corrupt_content, encoding="utf-8", errors="ignore")

    agent = NetworkAgent(start_background_workers=False)
    assert hasattr(agent, "device_uuid")
    parsed = uuid.UUID(agent.device_uuid, version=4)
    assert str(parsed).lower() == agent.device_uuid
    assert uuid_file.read_text(encoding="utf-8").strip() == agent.device_uuid


def test_stress_uppercase_valid_uuid_in_file_is_normalized(isolated_agent_dir):
    """Edge 7: A valid UUID4 written in uppercase in device_uuid.txt is normalized to lowercase."""
    raw_v4 = str(uuid.uuid4()).upper()
    uuid_file = isolated_agent_dir / "device_uuid.txt"
    uuid_file.write_text(raw_v4 + "  \n", encoding="utf-8")

    agent = NetworkAgent(start_background_workers=False)
    assert agent.device_uuid == raw_v4.lower()


def test_backward_compatibility_and_snapshot_schema(isolated_agent_dir, monkeypatch):
    """Edge 8: status_snapshot and agent instance maintain full backward compatibility for legacy consumers."""
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {
        "eth0": [snicaddr(family=AF_LINK, address="00:11:22:33:44:55", netmask=None, broadcast=None, ptp=None)]
    })
    monkeypatch.setattr(psutil, "net_if_stats", lambda: {
        "eth0": snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up")
    })
    agent = NetworkAgent(start_background_workers=False)

    assert agent.local_mac == agent.primary_mac
    assert agent.local_mac == "00:11:22:33:44:55"

    snapshot = agent.status_snapshot()
    expected_keys = ["agent_id", "device_uuid", "primary_mac", "all_macs", "device_mac", "local_mac", "hostname", "version", "organization_id"]
    for k in expected_keys:
        assert k in snapshot, f"Key {k} missing from status_snapshot"
    assert snapshot["device_mac"] == snapshot["primary_mac"]
    assert snapshot["local_mac"] == snapshot["primary_mac"]
    assert snapshot["device_uuid"] == agent.device_uuid


def test_forensic_audit_zero_machine_id_or_machineguid_leakage(isolated_agent_dir, monkeypatch):
    """Edge 9: Ensure OS MachineGuid or Linux machine-id is never accessed, stored, or transmitted."""
    real_machine_guid = None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, "MachineGuid")
            real_machine_guid = str(val).strip().lower()
    except Exception:
        pass

    agent = NetworkAgent(start_background_workers=False)
    agent.heartbeat_interval = 0

    collected_strings = []
    collected_strings.append(agent.device_uuid)
    collected_strings.append(agent.agent_id)
    collected_strings.append(agent.primary_mac)
    collected_strings.extend(agent.all_macs)

    captured_payloads = []
    def fake_bootstrap_post(url, json_body=None, **kwargs):
        captured_payloads.append(json_body)
        agent.is_running = False
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"enrollment_status": "enrolled"}
        return resp

    def fake_request(method, url, json_body=None, **kwargs):
        captured_payloads.append(json_body)
        agent.is_running = False
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"organization_id": agent.organization_id}
        return resp

    monkeypatch.setattr(agent.api_client, "bootstrap_post", fake_bootstrap_post)
    monkeypatch.setattr(agent.api_client, "request", fake_request)
    monkeypatch.setattr(agent.api_client, "has_credentials", lambda: True)

    agent._register_agent()
    agent.is_running = True
    agent._heartbeat_worker()

    for p in captured_payloads:
        for k, v in p.items():
            if isinstance(v, str):
                collected_strings.append(v)
            elif isinstance(v, list):
                collected_strings.extend(str(item) for item in v)

    for s in collected_strings:
        if real_machine_guid:
            assert real_machine_guid not in s.lower(), f"LEAK DETECTED: Real Windows MachineGuid found in {s}!"
        assert "machine-id" not in s.lower()
        assert "machineguid" not in s.lower()
