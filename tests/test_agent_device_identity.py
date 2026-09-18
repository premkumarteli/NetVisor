"""
Unit tests for Agent-Side Persistent UUID & Multi-NIC Interface Discovery.
Covers Requirements R1 and R2 from ORIGINAL_REQUEST.md and PROJECT.md.

Scenarios tested:
1. test_device_uuid_persists_to_disk_and_reuses_across_restarts
2. test_device_uuid_regenerates_when_runtime_dir_wiped
3. test_multi_nic_enumeration_filters_loopback_and_invalid_macs
4. test_primary_mac_correlates_to_outbound_ip
5. test_registration_payload_contains_hybrid_identity
6. test_heartbeat_payload_contains_hybrid_identity
7. test_disconnected_fallback_uses_first_valid_mac
"""

from __future__ import annotations

import collections
import os
import socket
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import psutil
import pytest

import agent.main as agent_main
from agent.main import NetworkAgent


snicaddr = collections.namedtuple("snicaddr", ["family", "address", "netmask", "broadcast", "ptp"])
snicstats = collections.namedtuple("snicstats", ["isup", "duplex", "speed", "mtu", "flags"])
AF_LINK = getattr(psutil, "AF_LINK", -1)


@pytest.fixture
def mock_agent_env(tmp_path, monkeypatch):
    """Isolates agent runtime directory and neutralizes external network/hardware dependencies."""
    runtime_dir = tmp_path / "runtime" / "agent"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(agent_main, "AGENT_RUNTIME_DIR", runtime_dir)
    monkeypatch.setenv("NETVISOR_AGENT_RUNTIME_DIR", str(runtime_dir))
    return runtime_dir


def test_device_uuid_persists_to_disk_and_reuses_across_restarts(mock_agent_env):
    """
    R1: Agent generates a persistent RFC 4122 UUID4 on first run, saves it to
    AGENT_RUNTIME_DIR / 'device_uuid.txt', and reuses the exact same UUID across restarts.
    """
    uuid_file = mock_agent_env / "device_uuid.txt"
    assert not uuid_file.exists(), "device_uuid.txt should not exist before first run"

    agent1 = NetworkAgent(start_background_workers=False)

    assert hasattr(agent1, "device_uuid"), "NetworkAgent must expose 'device_uuid' attribute"
    assert isinstance(agent1.device_uuid, str), "device_uuid must be a string"
    parsed_uuid = uuid.UUID(agent1.device_uuid, version=4)
    assert str(parsed_uuid) == agent1.device_uuid, "device_uuid must be canonical lowercase RFC 4122 UUID4"

    assert uuid_file.exists(), "device_uuid.txt must be created on disk"
    persisted = uuid_file.read_text(encoding="utf-8").strip()
    assert persisted == agent1.device_uuid, "Persisted UUID must match agent1.device_uuid"

    # Simulate process restart
    agent2 = NetworkAgent(start_background_workers=False)
    assert hasattr(agent2, "device_uuid"), "Restarted agent must expose 'device_uuid'"
    assert agent2.device_uuid == agent1.device_uuid, (
        f"Restarted agent generated new UUID {agent2.device_uuid} instead of reusing {agent1.device_uuid}"
    )


def test_device_uuid_regenerates_when_runtime_dir_wiped(mock_agent_env):
    """
    R1: When the agent runtime directory is wiped (e.g. reinstallation),
    the agent generates a new persistent UUID4 and stores it.
    """
    agent1 = NetworkAgent(start_background_workers=False)
    assert hasattr(agent1, "device_uuid"), "NetworkAgent must expose 'device_uuid'"
    initial_uuid = agent1.device_uuid

    uuid_file = mock_agent_env / "device_uuid.txt"
    assert uuid_file.exists()
    uuid_file.unlink()

    # Re-instantiate agent simulating fresh reinstallation
    agent2 = NetworkAgent(start_background_workers=False)
    assert hasattr(agent2, "device_uuid"), "Reinstalled agent must expose 'device_uuid'"
    assert agent2.device_uuid != initial_uuid, "Agent must regenerate UUID when runtime directory is wiped"
    assert uuid.UUID(agent2.device_uuid, version=4), "Regenerated UUID must be valid RFC 4122 UUID4"
    assert uuid_file.read_text(encoding="utf-8").strip() == agent2.device_uuid


def test_multi_nic_enumeration_filters_loopback_and_invalid_macs(mock_agent_env, monkeypatch):
    """
    R2: Multi-NIC enumeration extracts all valid, active, non-loopback unicast MACs,
    filtering out loopback interfaces, all-zeros, broadcast, and multicast addresses.
    """
    mock_addrs = {
        "lo": [
            snicaddr(family=socket.AF_INET, address="127.0.0.1", netmask="255.0.0.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:00:00:00:00:00", netmask=None, broadcast=None, ptp=None),
        ],
        "Loopback Pseudo-Interface 1": [
            snicaddr(family=AF_LINK, address="00:00:00:00:00:00", netmask=None, broadcast=None, ptp=None),
        ],
        "eth0": [
            snicaddr(family=socket.AF_INET, address="192.168.1.10", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="02:00:00:00:00:01", netmask=None, broadcast=None, ptp=None),
        ],
        "wlan0": [
            snicaddr(family=socket.AF_INET, address="10.0.0.25", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:11:22:33:44:55", netmask=None, broadcast=None, ptp=None),
        ],
        "bcast_adapter": [
            snicaddr(family=AF_LINK, address="ff:ff:ff:ff:ff:ff", netmask=None, broadcast=None, ptp=None),
        ],
        "mcast_adapter": [
            snicaddr(family=AF_LINK, address="01:00:5e:00:00:01", netmask=None, broadcast=None, ptp=None),
        ],
        "bad_nic": [
            snicaddr(family=AF_LINK, address="not-a-valid-mac", netmask=None, broadcast=None, ptp=None),
        ],
        "empty_nic": [
            snicaddr(family=AF_LINK, address="", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {nic: snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up") for nic in mock_addrs}

    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)

    agent = NetworkAgent(start_background_workers=False)

    assert hasattr(agent, "all_macs"), "NetworkAgent must expose 'all_macs' attribute"
    assert isinstance(agent.all_macs, list), "'all_macs' must be a list of strings"

    expected_valid = {"02:00:00:00:00:01", "00:11:22:33:44:55"}
    assert set(agent.all_macs) == expected_valid, (
        f"all_macs should contain only valid unicast MACs {expected_valid}, got {agent.all_macs}"
    )
    assert "00:00:00:00:00:00" not in agent.all_macs, "Loopback / all-zero MAC must be filtered"
    assert "ff:ff:ff:ff:ff:ff" not in agent.all_macs, "Broadcast MAC must be filtered"
    assert "01:00:5e:00:00:01" not in agent.all_macs, "Multicast MAC must be filtered"


def test_primary_mac_correlates_to_outbound_ip(mock_agent_env, monkeypatch):
    """
    R2: Primary MAC must be selected by correlating local interfaces against
    the outbound routing IP (_detect_local_ip), placing primary_mac first in all_macs.
    """
    mock_addrs = {
        "eth0": [
            snicaddr(family=socket.AF_INET, address="192.168.1.100", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:aa:bb:cc:dd:ee", netmask=None, broadcast=None, ptp=None),
        ],
        "wlan0": [
            snicaddr(family=socket.AF_INET, address="10.0.0.50", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:11:22:33:44:55", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {
        "eth0": snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up"),
        "wlan0": snicstats(isup=True, duplex=0, speed=300, mtu=1500, flags="up"),
    }

    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)
    # Simulate outbound routing through wlan0 (10.0.0.50)
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "10.0.0.50")

    agent = NetworkAgent(start_background_workers=False)

    assert hasattr(agent, "primary_mac"), "NetworkAgent must expose 'primary_mac'"
    assert agent.primary_mac == "00:11:22:33:44:55", (
        f"primary_mac should correlate to 10.0.0.50 ('00:11:22:33:44:55'), got {agent.primary_mac}"
    )
    assert hasattr(agent, "all_macs"), "NetworkAgent must expose 'all_macs'"
    assert agent.all_macs[0] == "00:11:22:33:44:55", "primary_mac must be first element in all_macs"
    assert "00:aa:bb:cc:dd:ee" in agent.all_macs, "Secondary MAC must be included in all_macs"
    assert agent.local_mac == agent.primary_mac, "local_mac must equal primary_mac for backward compatibility"


def test_registration_payload_contains_hybrid_identity(mock_agent_env, monkeypatch):
    """
    R2: Registration payload sent to POST /api/v1/agents/register must include:
    device_uuid, primary_mac, all_macs, and backward-compatible device_mac (= primary_mac).
    """
    mock_addrs = {
        "eth0": [
            snicaddr(family=socket.AF_INET, address="192.168.1.100", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:11:22:33:44:55", netmask=None, broadcast=None, ptp=None),
        ],
        "eth1": [
            snicaddr(family=socket.AF_INET, address="192.168.2.100", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="aa:bb:cc:dd:ee:ff", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {nic: snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up") for nic in mock_addrs}
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "192.168.1.100")

    agent = NetworkAgent(start_background_workers=False)

    captured_payloads = []

    def fake_bootstrap_post(url, json_body=None, **kwargs):
        captured_payloads.append(json_body)
        agent.is_running = False  # Exit retry loop
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"enrollment_status": "enrolled"}
        return resp

    monkeypatch.setattr(agent.api_client, "bootstrap_post", fake_bootstrap_post)
    monkeypatch.setattr(agent.api_client, "has_credentials", lambda: True)

    agent._register_agent(force_reenroll=False)

    assert len(captured_payloads) == 1, "Agent must issue registration POST"
    payload = captured_payloads[0]

    assert "device_uuid" in payload, "Registration payload must include 'device_uuid'"
    assert payload["device_uuid"] == agent.device_uuid, "Payload 'device_uuid' must match agent.device_uuid"
    assert "primary_mac" in payload, "Registration payload must include 'primary_mac'"
    assert payload["primary_mac"] == agent.primary_mac, "Payload 'primary_mac' must match agent.primary_mac"
    assert "all_macs" in payload, "Registration payload must include 'all_macs'"
    assert payload["all_macs"] == agent.all_macs, "Payload 'all_macs' must match agent.all_macs"
    assert payload.get("device_mac") == agent.primary_mac, (
        "Backward-compatible 'device_mac' must equal primary_mac"
    )


def test_heartbeat_payload_contains_hybrid_identity(mock_agent_env, monkeypatch):
    """
    R2: Heartbeat payload sent to POST /api/v1/agents/heartbeat must include:
    device_uuid, primary_mac, all_macs, and device_mac (= primary_mac).
    """
    mock_addrs = {
        "eth0": [
            snicaddr(family=socket.AF_INET, address="192.168.1.100", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:11:22:33:44:55", netmask=None, broadcast=None, ptp=None),
        ],
        "eth1": [
            snicaddr(family=socket.AF_INET, address="192.168.2.100", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="aa:bb:cc:dd:ee:ff", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {nic: snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up") for nic in mock_addrs}
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "192.168.1.100")

    agent = NetworkAgent(start_background_workers=False)

    captured_payloads = []

    def fake_request(method, url, json_body=None, **kwargs):
        captured_payloads.append(json_body)
        agent.is_running = False  # Terminate worker loop after first heartbeat
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"organization_id": agent.organization_id}
        return resp

    monkeypatch.setattr(agent.api_client, "has_credentials", lambda: True)
    monkeypatch.setattr(agent.api_client, "request", fake_request)

    agent._heartbeat_worker()

    assert len(captured_payloads) == 1, "Agent must issue heartbeat POST"
    payload = captured_payloads[0]

    assert "device_uuid" in payload, "Heartbeat payload must include 'device_uuid'"
    assert payload["device_uuid"] == agent.device_uuid, "Payload 'device_uuid' must match agent.device_uuid"
    assert "primary_mac" in payload, "Heartbeat payload must include 'primary_mac'"
    assert payload["primary_mac"] == agent.primary_mac, "Payload 'primary_mac' must match agent.primary_mac"
    assert "all_macs" in payload, "Heartbeat payload must include 'all_macs'"
    assert payload["all_macs"] == agent.all_macs, "Payload 'all_macs' must match agent.all_macs"
    assert payload.get("device_mac") == agent.primary_mac, (
        "Backward-compatible 'device_mac' must equal primary_mac"
    )


def test_disconnected_fallback_uses_first_valid_mac(mock_agent_env, monkeypatch):
    """
    R2: When an agent starts up completely disconnected (_detect_local_ip returns 127.0.0.1),
    it cleanly falls back to using the first valid physical MAC from all_macs as primary_mac
    without crashing or selecting loopback.
    """
    mock_addrs = {
        "lo": [
            snicaddr(family=socket.AF_INET, address="127.0.0.1", netmask="255.0.0.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:00:00:00:00:00", netmask=None, broadcast=None, ptp=None),
        ],
        "eth0": [
            snicaddr(family=AF_LINK, address="00:11:22:33:44:55", netmask=None, broadcast=None, ptp=None),
        ],
        "eth1": [
            snicaddr(family=AF_LINK, address="00:aa:bb:cc:dd:ee", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {nic: snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up") for nic in mock_addrs}
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)
    # Simulate disconnected host
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "127.0.0.1")

    agent = NetworkAgent(start_background_workers=False)

    assert hasattr(agent, "primary_mac"), "NetworkAgent must expose 'primary_mac'"
    assert agent.primary_mac == "00:11:22:33:44:55", (
        f"Disconnected agent should fall back to first valid MAC '00:11:22:33:44:55', got {agent.primary_mac}"
    )
    assert agent.local_mac == agent.primary_mac, "local_mac must equal primary_mac"
    assert agent.all_macs == ["00:11:22:33:44:55", "00:aa:bb:cc:dd:ee"]
