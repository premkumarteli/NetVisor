from backend.utils.network import (
    classify_ip_scope,
    is_rfc1918_device_ip,
    is_unicast_mac,
    normalize_ip,
    normalize_mac,
    resolve_source_ip,
)


class _FakeRequest:
    def __init__(self, client, headers=None):
        self.client = client
        self.headers = headers or {}


def test_rfc1918_device_ip_is_strict_to_supported_lan_ranges():
    assert is_rfc1918_device_ip("10.10.10.10") is True
    assert is_rfc1918_device_ip("172.16.1.25") is True
    assert is_rfc1918_device_ip("192.168.1.10") is True
    assert is_rfc1918_device_ip("172.15.1.25") is False
    assert is_rfc1918_device_ip("169.254.1.10") is False
    assert is_rfc1918_device_ip("8.8.8.8") is False


def test_ip_scope_classification_separates_internal_external_and_control():
    assert classify_ip_scope("10.128.88.96") == "internal"
    assert classify_ip_scope("8.8.8.8") == "external"
    assert classify_ip_scope("255.255.255.255") == "control"
    assert classify_ip_scope("224.0.0.1") == "control"
    assert classify_ip_scope("not-an-ip") == "invalid"


def test_mac_normalization_and_unicast_filtering():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert is_unicast_mac("aa:bb:cc:dd:ee:ff") is True
    assert is_unicast_mac("ff:ff:ff:ff:ff:ff") is False
    assert normalize_ip(" 10.0.0.5 ") == "10.0.0.5"


def test_source_ip_does_not_trust_forwarded_headers_without_a_peer_address():
    request = _FakeRequest(
        client=None,
        headers={"X-Forwarded-For": "203.0.113.99", "X-Real-IP": "203.0.113.99"},
    )

    assert resolve_source_ip(request) == "unknown"


def test_source_ip_uses_direct_peer_when_proxy_is_not_trusted(monkeypatch):
    from backend.core.config import settings

    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "127.0.0.1")
    request = _FakeRequest(
        client=type("Client", (), {"host": "198.51.100.7"})(),
        headers={"X-Forwarded-For": "203.0.113.99"},
    )

    assert resolve_source_ip(request) == "198.51.100.7"
