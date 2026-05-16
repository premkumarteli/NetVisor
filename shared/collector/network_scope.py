"""Collector-side network scope and ignore policy.

This module keeps packet acceptance decisions close to the collectors so noisy
control traffic, accidental WAN-only captures, and gateway self-traffic do not
pollute flow/device truth before records reach the backend.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import Iterable


CONTROL_REASONS = {
    "invalid",
    "multicast",
    "broadcast",
    "loopback",
    "link_local",
    "unspecified",
    "reserved",
}


DEFAULT_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def normalize_ip(value: object) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def classify_ip_scope(value: object) -> str:
    normalized = normalize_ip(value)
    if not normalized:
        return "invalid"

    parsed = ipaddress.ip_address(normalized)
    if parsed.is_unspecified:
        return "unspecified"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_link_local:
        return "link_local"

    if isinstance(parsed, ipaddress.IPv4Address):
        octets = normalized.split(".")
        if normalized == "255.255.255.255" or octets[-1] == "255":
            return "broadcast"
        if any(parsed in network for network in DEFAULT_PRIVATE_NETWORKS):
            return "internal"

    if parsed.is_reserved:
        return "reserved"

    if parsed.is_private:
        return "internal"
    return "external"


def _split_values(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        values: list[str] = []
        for item in raw:
            values.extend(_split_values(item))
        return values
    text = str(raw).strip()
    if not text:
        return []
    return [part.strip() for part in text.replace(";", ",").split(",") if part.strip()]


NetworkType = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_networks(values: Iterable[object]) -> tuple[tuple[NetworkType, ...], tuple[str, ...]]:
    networks: list[NetworkType] = []
    invalid: list[str] = []
    for value in values:
        for raw in _split_values(value):
            try:
                networks.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                invalid.append(raw)
    return tuple(networks), tuple(invalid)


def _parse_ips(values: Iterable[object]) -> tuple[frozenset[str], tuple[str, ...]]:
    ips: set[str] = set()
    invalid: list[str] = []
    for value in values:
        for raw in _split_values(value):
            normalized = normalize_ip(raw)
            if normalized:
                ips.add(normalized)
            else:
                invalid.append(raw)
    return frozenset(ips), tuple(invalid)


def _env(*names: str) -> list[str]:
    return [os.getenv(name, "") for name in names if os.getenv(name, "").strip()]


def _config_values(config: dict | None, *names: str) -> list[object]:
    if not isinstance(config, dict):
        return []
    values: list[object] = []
    for name in names:
        if name in config:
            values.append(config.get(name))
    return values


@dataclass(frozen=True)
class PacketScopeDecision:
    accepted: bool
    reason: str


@dataclass
class PacketScopePolicy:
    role: str = "agent"
    allowed_networks: tuple[NetworkType, ...] = field(default_factory=tuple)
    ignored_ips: frozenset[str] = field(default_factory=frozenset)
    ignore_mode: str = "off"
    invalid_networks: tuple[str, ...] = field(default_factory=tuple)
    invalid_ips: tuple[str, ...] = field(default_factory=tuple)
    filtered_packets: int = 0
    accepted_packets: int = 0
    last_filter_reason: str | None = None

    @classmethod
    def from_env(
        cls,
        *,
        role: str = "agent",
        config: dict | None = None,
        local_ip: str | None = None,
    ) -> "PacketScopePolicy":
        network_values: list[object] = []
        network_values.extend(_env("NETVISOR_NETWORK_SCOPE", "NETVISOR_USER_LAN_PREFIXES"))
        network_values.extend(_config_values(config, "network_scope", "user_lan_prefixes", "allowed_networks"))

        allowed_networks, invalid_networks = _parse_networks(network_values)
        if not allowed_networks:
            allowed_networks = DEFAULT_PRIVATE_NETWORKS

        ignore_values: list[object] = []
        ignore_values.extend(_env("NETVISOR_IGNORE_IPS", "NETVISOR_COLLECTOR_IGNORE_IPS"))
        ignore_values.extend(_config_values(config, "ignore_ips", "collector_ignore_ips"))

        if role == "gateway":
            ignore_values.extend(_env("NETVISOR_GATEWAY_IP", "NETVISOR_GATEWAY_IGNORE_IPS"))
            ignore_values.extend(_config_values(config, "gateway_ip", "gateway_ignore_ips"))
        elif role == "agent":
            ignore_values.extend(_env("NETVISOR_AGENT_IGNORE_IPS"))
            ignore_values.extend(_config_values(config, "agent_ignore_ips"))

        if local_ip and str(os.getenv("NETVISOR_IGNORE_LOCAL_IP", "")).strip().lower() in {"1", "true", "yes", "on"}:
            ignore_values.append(local_ip)

        ignored_ips, invalid_ips = _parse_ips(ignore_values)
        mode = (
            os.getenv(f"NETVISOR_{role.upper()}_IGNORE_MODE")
            or os.getenv("NETVISOR_GATEWAY_IGNORE_MODE" if role == "gateway" else "NETVISOR_COLLECTOR_IGNORE_MODE")
            or str((config or {}).get("gateway_ignore_mode" if role == "gateway" else "ignore_mode", "off"))
            or "off"
        ).strip().lower()

        if mode in {"1", "true", "yes", "on", "drop", "strict"}:
            mode = "drop"
        elif mode in {"warn", "mark"}:
            mode = "mark"
        else:
            mode = "off"

        return cls(
            role=role,
            allowed_networks=tuple(allowed_networks),
            ignored_ips=ignored_ips,
            ignore_mode=mode,
            invalid_networks=invalid_networks,
            invalid_ips=invalid_ips,
        )

    def should_accept_ips(self, src_ip: object, dst_ip: object) -> PacketScopeDecision:
        src = normalize_ip(src_ip)
        dst = normalize_ip(dst_ip)
        if not src or not dst:
            return self._decision(False, "invalid_ip")

        src_scope = classify_ip_scope(src)
        dst_scope = classify_ip_scope(dst)
        if src_scope in CONTROL_REASONS and dst_scope in CONTROL_REASONS:
            return self._decision(False, f"control_traffic:{src_scope}->{dst_scope}")

        if self.ignore_mode == "drop" and (src in self.ignored_ips or dst in self.ignored_ips):
            return self._decision(False, "ignored_endpoint")

        if self.allowed_networks:
            src_addr = ipaddress.ip_address(src)
            dst_addr = ipaddress.ip_address(dst)
            if not any(src_addr in network or dst_addr in network for network in self.allowed_networks):
                return self._decision(False, "outside_network_scope")

        return self._decision(True, "accepted")

    def should_accept_observation(self, observation: object) -> PacketScopeDecision:
        return self.should_accept_ips(
            getattr(observation, "src_ip", None),
            getattr(observation, "dst_ip", None),
        )

    def status_snapshot(self) -> dict:
        return {
            "role": self.role,
            "allowed_networks": [str(network) for network in self.allowed_networks],
            "ignored_ips": sorted(self.ignored_ips),
            "ignore_mode": self.ignore_mode,
            "invalid_networks": list(self.invalid_networks),
            "invalid_ips": list(self.invalid_ips),
            "accepted_packets": self.accepted_packets,
            "filtered_packets": self.filtered_packets,
            "last_filter_reason": self.last_filter_reason,
        }

    def _decision(self, accepted: bool, reason: str) -> PacketScopeDecision:
        if accepted:
            self.accepted_packets += 1
        else:
            self.filtered_packets += 1
            self.last_filter_reason = reason
        return PacketScopeDecision(accepted=accepted, reason=reason)


def build_scope_policy(
    *,
    role: str = "agent",
    config: dict | None = None,
    local_ip: str | None = None,
) -> PacketScopePolicy:
    return PacketScopePolicy.from_env(role=role, config=config, local_ip=local_ip)


def summarize_scope_policy(policy: PacketScopePolicy) -> str:
    networks = ", ".join(str(network) for network in policy.allowed_networks) or "none"
    ignored = ", ".join(sorted(policy.ignored_ips)) or "none"
    return f"scope={networks}; ignore_mode={policy.ignore_mode}; ignored_ips={ignored}"
