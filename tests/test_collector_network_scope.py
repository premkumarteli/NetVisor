from shared.collector.network_scope import (
    PacketScopePolicy,
    build_scope_policy,
    classify_ip_scope,
    normalize_ip,
)


class DummyObservation:
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip


def test_ip_classification_matches_collector_needs():
    assert normalize_ip(" 192.168.1.10 ") == "192.168.1.10"
    assert classify_ip_scope("10.1.2.3") == "internal"
    assert classify_ip_scope("8.8.8.8") == "external"
    assert classify_ip_scope("255.255.255.255") == "broadcast"
    assert classify_ip_scope("224.0.0.1") == "multicast"
    assert classify_ip_scope("not-an-ip") == "invalid"


def test_default_policy_accepts_private_lan_flows():
    policy = PacketScopePolicy.from_env(role="agent", config={})
    decision = policy.should_accept_ips("192.168.1.10", "8.8.8.8")

    assert decision.accepted is True
    assert policy.accepted_packets == 1


def test_policy_rejects_flows_outside_configured_scope():
    policy = PacketScopePolicy.from_env(
        role="gateway",
        config={"network_scope": "192.168.50.0/24"},
    )
    decision = policy.should_accept_observation(DummyObservation("10.1.1.20", "8.8.8.8"))

    assert decision.accepted is False
    assert decision.reason == "outside_network_scope"
    assert policy.filtered_packets == 1


def test_gateway_ignore_mode_drops_configured_gateway_ip():
    policy = PacketScopePolicy.from_env(
        role="gateway",
        config={
            "network_scope": "192.168.137.0/24",
            "gateway_ip": "192.168.137.1",
            "gateway_ignore_mode": "drop",
        },
    )

    decision = policy.should_accept_ips("192.168.137.1", "192.168.137.42")

    assert decision.accepted is False
    assert decision.reason == "ignored_endpoint"


def test_invalid_scope_values_are_reported_without_breaking_policy():
    policy = build_scope_policy(
        role="agent",
        config={
            "network_scope": ["not-a-cidr", "192.168.1.0/24"],
            "ignore_ips": ["bad-ip", "192.168.1.1"],
        },
    )

    assert policy.invalid_networks == ("not-a-cidr",)
    assert policy.invalid_ips == ("bad-ip",)
    assert "192.168.1.1" in policy.ignored_ips
