"""
Challenger Empirical Stress-Test Suite for Milestone 1:
Agent UUID Persistence & Multi-NIC Discovery.

Covers adversarial scenarios:
1. Multicast MAC rejection (01:00:5e:*, 33:33:*, 01:80:c2:*, 03:*, odd first octets)
2. Broadcast and loopback MAC rejection
3. Synthetic NICs (dummy, veth, bridges, docker)
4. Hypervisor adapters (VMware, VirtualBox, Hyper-V, KVM)
5. VPN/tunnel adapters (WireGuard without MAC, TAP with MAC, point-to-point)
6. Corrupt device_uuid.txt handling (empty, junk, UUIDv1, UUIDv5, braces, uppercase)
7. All interfaces down fallback
8. psutil exception resilience (empty/failing net_if_addrs and net_if_stats)
9. Concurrent instantiation and race condition exploration
10. Loopback interface name boundary testing
11. Multi-NIC deduplication and status snapshot integrity
"""

from __future__ import annotations

import collections
import concurrent.futures
import os
import socket
import threading
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import psutil
import pytest

import agent.main as agent_main
from agent.device_detector import DeviceDetector, enumerate_local_interfaces, is_loopback_interface, normalize_mac
from agent.main import NetworkAgent

snicaddr = collections.namedtuple("snicaddr", ["family", "address", "netmask", "broadcast", "ptp"])
snicstats = collections.namedtuple("snicstats", ["isup", "duplex", "speed", "mtu", "flags"])
AF_LINK = getattr(psutil, "AF_LINK", -1)


@pytest.fixture
def isolated_agent_env(tmp_path, monkeypatch):
    """Isolates agent runtime directory and neutralizes external network/hardware dependencies."""
    runtime_dir = tmp_path / "runtime" / "agent"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(agent_main, "AGENT_RUNTIME_DIR", runtime_dir)
    monkeypatch.setenv("NETVISOR_AGENT_RUNTIME_DIR", str(runtime_dir))
    return runtime_dir


# =========================================================================
# 1. MULTICAST AND BROADCAST MAC ADVERSARIAL STRESS TESTS
# =========================================================================

@pytest.mark.parametrize(
    "multicast_mac",
    [
        "01:00:5e:00:00:01",  # IPv4 all-systems multicast
        "01:00:5e:7f:ff:ff",  # IPv4 multicast boundary
        "33:33:00:00:00:01",  # IPv6 all-nodes multicast
        "33:33:ff:12:34:56",  # IPv6 solicited-node multicast
        "01:80:c2:00:00:00",  # Spanning tree BPDU multicast
        "01:80:c2:00:00:03",  # 802.1X PAE multicast
        "01:0c:cd:01:00:01",  # IEC 61850 GOOSE multicast
        "03:00:00:00:00:01",  # Locally administered multicast (LSB of first byte is 1)
        "09:00:2b:00:00:0f",  # DECnet multicast
        "11:22:33:44:55:66",  # Generic multicast (0x11 is odd)
        "ff:11:22:33:44:55",  # Multicast (0xff is odd)
        "01-00-5e-00-00-01",  # Hyphen format multicast
        "33-33-00-00-00-01",  # Hyphen format IPv6 multicast
    ],
)
def test_normalize_mac_rejects_all_multicast_macs(multicast_mac):
    """Verify normalize_mac strictly rejects any MAC where IEEE 802 group/multicast bit is 1."""
    assert normalize_mac(multicast_mac) is None, f"Should reject multicast MAC: {multicast_mac}"


@pytest.mark.parametrize(
    "invalid_or_broadcast_mac",
    [
        "ff:ff:ff:ff:ff:ff",
        "FF:FF:FF:FF:FF:FF",
        "ff-ff-ff-ff-ff-ff",
        "00:00:00:00:00:00",
        "00-00-00-00-00-00",
        "",
        "   ",
        None,
        12345,
        "00:11:22:33:44",        # 5 octets
        "00:11:22:33:44:55:66",  # 7 octets
        "00:11:22:33:44:gg",     # Invalid hex
        "00:11:22:33:44:5",      # Short octet
        "00:11:22:33:44:005",    # Long octet
        "fe80::1ff:fe23:4567",   # IPv6 address
        "192.168.1.1",           # IPv4 address
    ],
)
def test_normalize_mac_rejects_invalid_and_broadcast(invalid_or_broadcast_mac):
    """Verify normalize_mac rejects all non-standard, malformed, broadcast, and loopback strings."""
    assert normalize_mac(invalid_or_broadcast_mac) is None


@pytest.mark.parametrize(
    "valid_mac,expected",
    [
        ("00:11:22:33:44:55", "00:11:22:33:44:55"),
        ("00-11-22-33-44-55", "00:11:22:33:44:55"),
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("  02:00:00:00:00:01  ", "02:00:00:00:00:01"),  # Locally administered unicast
        ("52:54:00:12:34:56", "52:54:00:12:34:56"),      # QEMU/KVM unicast
        ("00:50:56:c0:00:01", "00:50:56:c0:00:01"),      # VMware unicast
        ("00:15:5d:01:02:03", "00:15:5d:01:02:03"),      # Hyper-V unicast
    ],
)
def test_normalize_mac_accepts_valid_unicast(valid_mac, expected):
    """Verify normalize_mac normalizes valid unicast MAC addresses to lowercase colon format."""
    assert normalize_mac(valid_mac) == expected


# =========================================================================
# 2. SYNTHETIC, HYPERVISOR, AND VIRTUAL NIC TESTS
# =========================================================================

def test_hypervisor_and_synthetic_interfaces(isolated_agent_env, monkeypatch):
    """
    Verify discovery with a mix of physical, VMware, Hyper-V, VirtualBox,
    and Docker bridge interfaces properly extracts valid unicast MACs.
    """
    mock_addrs = {
        "eth0": [
            snicaddr(family=socket.AF_INET, address="192.168.1.50", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="e4:54:e8:11:22:33", netmask=None, broadcast=None, ptp=None),  # Real NIC
        ],
        "vmnet1": [
            snicaddr(family=socket.AF_INET, address="192.168.120.1", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:50:56:c0:00:01", netmask=None, broadcast=None, ptp=None),  # VMware
        ],
        "vEthernet (Default Switch)": [
            snicaddr(family=socket.AF_INET, address="172.25.80.1", netmask="255.255.240.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:15:5d:22:33:44", netmask=None, broadcast=None, ptp=None),  # Hyper-V
        ],
        "vboxnet0": [
            snicaddr(family=socket.AF_INET, address="192.168.56.1", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="0a:00:27:00:00:00", netmask=None, broadcast=None, ptp=None),  # VirtualBox
        ],
        "docker0": [
            snicaddr(family=socket.AF_INET, address="172.17.0.1", netmask="255.255.0.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="02:42:0a:95:5a:aa", netmask=None, broadcast=None, ptp=None),  # Docker
        ],
    }
    mock_stats = {nic: snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up") for nic in mock_addrs}
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "192.168.1.50")

    agent = NetworkAgent(start_background_workers=False)

    assert agent.primary_mac == "e4:54:e8:11:22:33"
    assert len(agent.all_macs) == 5
    assert agent.all_macs[0] == "e4:54:e8:11:22:33"
    assert "00:50:56:c0:00:01" in agent.all_macs
    assert "00:15:5d:22:33:44" in agent.all_macs
    assert "0a:00:27:00:00:00" in agent.all_macs
    assert "02:42:0a:95:5a:aa" in agent.all_macs


# =========================================================================
# 3. VPN AND TUNNEL ADAPTER TESTS
# =========================================================================

def test_wireguard_tunnel_without_mac_falls_back_to_physical_mac(isolated_agent_env, monkeypatch):
    """
    WireGuard and TUN interfaces have no link-layer MAC address.
    When outbound routing points to WireGuard IP (e.g. 10.8.0.2),
    primary_mac must fall back cleanly to the physical adapter's MAC.
    """
    mock_addrs = {
        "eth0": [
            snicaddr(family=socket.AF_INET, address="192.168.1.100", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="aa:bb:cc:11:22:33", netmask=None, broadcast=None, ptp=None),
        ],
        "wg0": [
            snicaddr(family=socket.AF_INET, address="10.8.0.2", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {
        "eth0": snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up"),
        "wg0": snicstats(isup=True, duplex=0, speed=0, mtu=1420, flags="up"),
    }
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "10.8.0.2")

    agent = NetworkAgent(start_background_workers=False)

    assert agent.primary_mac == "aa:bb:cc:11:22:33"
    assert agent.all_macs == ["aa:bb:cc:11:22:33"]


def test_openvpn_tap_adapter_with_mac(isolated_agent_env, monkeypatch):
    """
    TAP-Windows / OpenVPN adapters report a MAC address.
    When routing through TAP, primary_mac correlates to TAP MAC,
    and physical MAC is retained in all_macs.
    """
    mock_addrs = {
        "Ethernet": [
            snicaddr(family=socket.AF_INET, address="192.168.1.20", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="10:65:30:aa:bb:cc", netmask=None, broadcast=None, ptp=None),
        ],
        "TAP-Windows Adapter V9": [
            snicaddr(family=socket.AF_INET, address="10.10.0.5", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:ff:4a:5b:6c:7d", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {nic: snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up") for nic in mock_addrs}
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "10.10.0.5")

    agent = NetworkAgent(start_background_workers=False)

    assert agent.primary_mac == "00:ff:4a:5b:6c:7d"
    assert agent.all_macs[0] == "00:ff:4a:5b:6c:7d"
    assert "10:65:30:aa:bb:cc" in agent.all_macs
    assert len(agent.all_macs) == 2


# =========================================================================
# 4. CORRUPT DEVICE_UUID.TXT RESILIENCE TESTS
# =========================================================================

@pytest.mark.parametrize(
    "corrupted_content",
    [
        "",                                         # Empty file (0 bytes)
        "   \r\n   ",                               # Whitespace only
        "not-a-valid-uuid-at-all",                  # Arbitrary junk
        "c9bf9e57-1685-4c89-bafb-ff5af830be8z",    # Invalid hex char 'z'
        "c9bf9e57-1685-4c89-bafb",                 # Incomplete UUID
        "c9bf9e5716854c89bafbff5af830be8a",        # 32 hex chars without hyphens
        "{c9bf9e57-1685-4c89-bafb-ff5af830be8a}",  # Braced UUID
        str(uuid.uuid1()),                         # UUIDv1 (timestamp based, wrong version)
        str(uuid.uuid3(uuid.NAMESPACE_DNS, "x")),  # UUIDv3 (MD5 based, wrong version)
        str(uuid.uuid5(uuid.NAMESPACE_DNS, "x")),  # UUIDv5 (SHA-1 based, wrong version)
        '{"device_uuid": "c9bf9e57-1685-4c89-bafb-ff5af830be8a"}',  # JSON payload instead of raw string
        "\x00\x00\x00\x00",                         # Null bytes binary corruption
    ],
)
def test_corrupt_device_uuid_regenerates_valid_uuid4(isolated_agent_env, corrupted_content):
    """
    R1: If device_uuid.txt exists but is corrupted, empty, or not a canonical RFC 4122 UUID4,
    the agent must cleanly recover, overwrite the file, and return a fresh valid UUID4.
    """
    uuid_file = isolated_agent_env / "device_uuid.txt"
    uuid_file.write_text(corrupted_content, encoding="utf-8", errors="replace")

    agent = NetworkAgent(start_background_workers=False)

    assert hasattr(agent, "device_uuid")
    assert isinstance(agent.device_uuid, str)
    parsed = uuid.UUID(agent.device_uuid, version=4)
    assert parsed.version == 4
    assert str(parsed) == agent.device_uuid
    assert agent.device_uuid != corrupted_content.strip().lower()

    # File on disk must have been overwritten with the clean new UUID
    disk_content = uuid_file.read_text(encoding="utf-8").strip()
    assert disk_content == agent.device_uuid


def test_uppercase_device_uuid_normalized_to_lowercase(isolated_agent_env):
    """
    If device_uuid.txt contains valid UUID4 in uppercase or with surrounding whitespace,
    it should be accepted and normalized to canonical lowercase.
    """
    valid_uuid4 = str(uuid.uuid4())
    uppercase_uuid = f"  {valid_uuid4.upper()}  \n"
    uuid_file = isolated_agent_env / "device_uuid.txt"
    uuid_file.write_text(uppercase_uuid, encoding="utf-8")

    agent = NetworkAgent(start_background_workers=False)

    assert agent.device_uuid == valid_uuid4.lower()


# =========================================================================
# 5. CONCURRENT INSTANTIATION & RACE CONDITION TESTS
# =========================================================================

def test_concurrent_agent_instantiation(isolated_agent_env):
    """
    Stress-test concurrent initialization of multiple NetworkAgent instances
    in separate threads before device_uuid.txt exists.
    """
    barrier = threading.Barrier(20)
    results = [None] * 20
    errors = []

    def init_worker(idx):
        try:
            barrier.wait(timeout=5)
            agent = NetworkAgent(start_background_workers=False)
            results[idx] = agent.device_uuid
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=init_worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Concurrent instantiation crashed with errors: {errors}"
    assert all(r is not None for r in results)
    for r in results:
        parsed = uuid.UUID(r, version=4)
        assert parsed.version == 4

    uuid_file = isolated_agent_env / "device_uuid.txt"
    assert uuid_file.exists()
    disk_uuid = uuid_file.read_text(encoding="utf-8").strip()
    assert uuid.UUID(disk_uuid, version=4)


# =========================================================================
# 6. RESILIENCE: ALL INTERFACES DOWN OR FAILING PSUTIL
# =========================================================================

def test_all_interfaces_down_fallback(isolated_agent_env, monkeypatch):
    """
    When all physical interfaces are down (is_up=False, e.g. cables unplugged),
    enumerate_local_interfaces must fall back to inactive interfaces
    rather than returning an empty list.
    """
    mock_addrs = {
        "eth0": [
            snicaddr(family=socket.AF_INET, address="192.168.1.10", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:11:22:33:44:55", netmask=None, broadcast=None, ptp=None),
        ],
        "eth1": [
            snicaddr(family=socket.AF_INET, address="192.168.2.10", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:66:77:88:99:aa", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {
        "eth0": snicstats(isup=False, duplex=0, speed=0, mtu=1500, flags="down"),
        "eth1": snicstats(isup=False, duplex=0, speed=0, mtu=1500, flags="down"),
    }
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "127.0.0.1")

    agent = NetworkAgent(start_background_workers=False)

    assert agent.primary_mac in {"00:11:22:33:44:55", "00:66:77:88:99:aa"}
    assert len(agent.all_macs) == 2
    assert "00:11:22:33:44:55" in agent.all_macs
    assert "00:66:77:88:99:aa" in agent.all_macs


def test_psutil_exceptions_graceful_fallback(isolated_agent_env, monkeypatch):
    """
    If psutil.net_if_addrs() or psutil.net_if_stats() raise an exception
    (e.g. PermissionError or OSError on restricted systems), the agent must
    not crash and must gracefully fall back to legacy node MAC.
    """
    def broken_net_if_addrs():
        raise PermissionError("Access denied to network interface tables")

    def broken_net_if_stats():
        raise OSError("Failed to query interface statistics")

    monkeypatch.setattr(psutil, "net_if_addrs", broken_net_if_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", broken_net_if_stats)

    agent = NetworkAgent(start_background_workers=False)

    assert hasattr(agent, "device_uuid")
    assert hasattr(agent, "primary_mac")
    assert hasattr(agent, "all_macs")
    assert isinstance(agent.all_macs, list)
    assert agent.primary_mac is not None


# =========================================================================
# 7. LOOPBACK INTERFACE NAME BOUNDARY TESTS
# =========================================================================

@pytest.mark.parametrize(
    "adapter_name,expected_is_loopback",
    [
        ("lo", True),
        ("lo0", True),
        ("lo1", True),
        ("lo99", True),
        ("Loopback Pseudo-Interface 1", True),
        ("Software Loopback Interface 1", True),
        ("loopback", True),
        ("Local Area Connection", False),       # Windows physical adapter name
        ("Local Area Connection 2", False),     # Windows physical adapter name
        ("Ethernet", False),
        ("Ethernet 2", False),
        ("Wi-Fi", False),
        ("wlan0", False),
        ("eth0", False),
        ("en0", False),
        ("enp3s0", False),
    ],
)
def test_is_loopback_interface_boundaries(adapter_name, expected_is_loopback):
    """
    Ensure is_loopback_interface correctly identifies loopback adapters
    without false-positive identification of Windows 'Local Area Connection' adapters.
    """
    assert is_loopback_interface(adapter_name) == expected_is_loopback


# =========================================================================
# 8. MULTI-NIC DEDUPLICATION & STATUS SNAPSHOT INTEGRITY
# =========================================================================

def test_bonded_nics_with_same_mac_deduplicated(isolated_agent_env, monkeypatch):
    """
    When NIC bonding / teaming / VLANs present the exact same MAC on multiple interfaces,
    all_macs must contain each unique MAC exactly once.
    """
    mock_addrs = {
        "eth0": [
            snicaddr(family=socket.AF_INET, address="192.168.1.10", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:11:22:33:44:55", netmask=None, broadcast=None, ptp=None),
        ],
        "eth0.100": [
            snicaddr(family=socket.AF_INET, address="192.168.100.10", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="00:11:22:33:44:55", netmask=None, broadcast=None, ptp=None),
        ],
        "eth1": [
            snicaddr(family=socket.AF_INET, address="192.168.2.10", netmask="255.255.255.0", broadcast=None, ptp=None),
            snicaddr(family=AF_LINK, address="aa:bb:cc:dd:ee:ff", netmask=None, broadcast=None, ptp=None),
        ],
    }
    mock_stats = {nic: snicstats(isup=True, duplex=0, speed=1000, mtu=1500, flags="up") for nic in mock_addrs}
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: mock_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: mock_stats)
    monkeypatch.setattr(NetworkAgent, "_detect_local_ip", lambda self: "192.168.1.10")

    agent = NetworkAgent(start_background_workers=False)

    assert agent.primary_mac == "00:11:22:33:44:55"
    assert agent.all_macs == ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]
    assert len(agent.all_macs) == 2, "Duplicate bonded MACs must be deduplicated in all_macs"


def test_status_snapshot_contains_all_identity_fields(isolated_agent_env, monkeypatch):
    """
    Ensure status_snapshot() correctly outputs device_uuid, primary_mac,
    all_macs, and backward-compatible device_mac.
    """
    agent = NetworkAgent(start_background_workers=False)
    snapshot = agent.status_snapshot()

    assert "device_uuid" in snapshot
    assert snapshot["device_uuid"] == agent.device_uuid
    assert "primary_mac" in snapshot
    assert snapshot["primary_mac"] == agent.primary_mac
    assert "all_macs" in snapshot
    assert snapshot["all_macs"] == agent.all_macs
    assert "device_mac" in snapshot
    assert snapshot["device_mac"] == agent.primary_mac
