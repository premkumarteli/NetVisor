from __future__ import annotations

import ipaddress
from typing import Optional


RFC1918_DEVICE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def normalize_ip(value: object) -> Optional[str]:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def is_rfc1918_device_ip(value: object) -> bool:
    ip_value = normalize_ip(value)
    if not ip_value:
        return False

    parsed = ipaddress.ip_address(ip_value)
    if parsed.version != 4:
        return False

    return any(parsed in network for network in RFC1918_DEVICE_NETWORKS)


def is_multicast_or_broadcast_ip(value: object) -> bool:
    ip_value = normalize_ip(value)
    if not ip_value:
        return False

    parsed = ipaddress.ip_address(ip_value)
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_loopback:
        return True

    if isinstance(parsed, ipaddress.IPv4Address):
        octets = ip_value.split(".")
        if octets[-1] == "255":
            return True
    return False


def classify_ip_scope(value: object) -> str:
    ip_value = normalize_ip(value)
    if not ip_value:
        return "invalid"
    if is_multicast_or_broadcast_ip(ip_value):
        return "control"
    if is_rfc1918_device_ip(ip_value):
        return "internal"
    return "external"


def normalize_ip_v2(value: object) -> Optional[str]:
    """
    Normalizes an IP address, converting IPv4-mapped IPv6 addresses to standard IPv4.
    """
    if value is None:
        return None
    try:
        ip_obj = ipaddress.ip_address(str(value).strip())
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
            ip_obj = ip_obj.ipv4_mapped
        return str(ip_obj)
    except ValueError:
        return None


def classify_ip_scope_v2(
    ip_value: str,
    organization_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | list[str],
    infrastructure_ips: set[str] | list[str],
    infrastructure_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | list[str] = None,
) -> str:
    """
    Classifies an IP address scope dynamically using organization CIDRs and infrastructure registries.
    Supports subnet-aware broadcast checks and CIDR-range infrastructure membership checks.
    """
    if not ip_value:
        return "UNSPECIFIED"
    
    try:
        ip_obj = ipaddress.ip_address(ip_value.strip())
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
            ip_obj = ip_obj.ipv4_mapped
    except ValueError:
        return "UNSPECIFIED"

    normalized_ip_str = str(ip_obj)

    if ip_obj.is_multicast:
        return "MULTICAST"
    if ip_obj.is_loopback:
        return "LOOPBACK"
    if ip_obj.is_unspecified:
        return "UNSPECIFIED"
    if ip_obj.is_link_local:
        return "LINK_LOCAL"

    # Broadcast check
    if normalized_ip_str == "255.255.255.255":
        return "BROADCAST"
        
    # Subnet-aware broadcast checks
    for network in organization_cidrs:
        try:
            net_obj = ipaddress.ip_network(network) if isinstance(network, str) else network
            if (
                isinstance(net_obj, ipaddress.IPv4Network)
                and ip_obj == net_obj.broadcast_address
            ):
                return "BROADCAST"
        except Exception:
            continue

    # Infrastructure checks
    if normalized_ip_str in infrastructure_ips:
        return "INFRASTRUCTURE"

    if infrastructure_nets:
        for net in infrastructure_nets:
            try:
                net_obj = ipaddress.ip_network(net) if isinstance(net, str) else net
                if ip_obj in net_obj:
                    return "INFRASTRUCTURE"
            except Exception:
                continue

    # Internal checks
    for net in organization_cidrs:
        try:
            net_obj = ipaddress.ip_network(net) if isinstance(net, str) else net
            if ip_obj in net_obj:
                return "INTERNAL"
        except Exception:
            continue

    # Fallback to standard is_private if organization networks are not configured
    if not organization_cidrs and ip_obj.is_private:
        return "INTERNAL"

    return "EXTERNAL"


def normalize_mac(value: object) -> Optional[str]:
    if value is None:
        return None

    raw = str(value).strip().lower()
    if not raw or raw in {"-", "unknown", "none", "null"}:
        return None

    candidate = raw.replace("-", ":").replace(".", "")
    if "." in raw and len(candidate) == 12:
        candidate = ":".join(candidate[index:index + 2] for index in range(0, 12, 2))

    parts = candidate.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        return None

    try:
        normalized = ":".join(f"{int(part, 16):02x}" for part in parts)
    except ValueError:
        return None

    if normalized == "ff:ff:ff:ff:ff:ff":
        return None
    return normalized


def is_unicast_mac(value: object) -> bool:
    normalized = normalize_mac(value)
    if not normalized:
        return False

    first_octet = int(normalized.split(":")[0], 16)
    return (first_octet & 1) == 0


def resolve_source_ip(request: Request) -> str:
    """
    Resolves the client IP address securely.
    Only trusts X-Forwarded-For or X-Real-IP if the direct connection
    is from a configured trusted proxy (NETVISOR_TRUSTED_PROXIES).
    """
    from fastapi import Request
    from backend.core.config import settings

    client = getattr(request, "client", None)
    if client is None:
        if hasattr(request, "headers"):
            forwarded_for = str(request.headers.get("X-Forwarded-For") or "").strip()
            if forwarded_for:
                parts = [p.strip() for p in forwarded_for.split(",")]
                if parts and parts[0]:
                    return parts[0]
            real_ip = str(request.headers.get("X-Real-IP") or "").strip()
            if real_ip:
                return real_ip
        return "unknown"

    socket_ip = str(client.host).strip()

    trusted_proxies = {p.strip() for p in (settings.TRUSTED_PROXIES or "").split(",") if p.strip()}
    if socket_ip in trusted_proxies and hasattr(request, "headers"):
        forwarded_for = str(request.headers.get("X-Forwarded-For") or "").strip()
        if forwarded_for:
            # First IP in X-Forwarded-For is the original client
            parts = [p.strip() for p in forwarded_for.split(",")]
            if parts and parts[0]:
                return parts[0]
        real_ip = str(request.headers.get("X-Real-IP") or "").strip()
        if real_ip:
            return real_ip

    return socket_ip
