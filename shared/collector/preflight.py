from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from socket import gethostbyname
from urllib.parse import urlparse
import json
import logging
import socket

try:
    import requests
except Exception:  # pragma: no cover - optional dependency in probe environments
    requests = None

logger = logging.getLogger("netvisor.collector.preflight")


@dataclass(frozen=True)
class PreflightResult:
    check_name: str
    passed: bool
    message: str
    severity: str = "info"


def _result(check_name: str, passed: bool, message: str, severity: str = "info") -> PreflightResult:
    return PreflightResult(check_name=check_name, passed=passed, message=message, severity=severity)


def _check_config_valid(config_path: Path, server_url: str | None) -> PreflightResult:
    if not config_path.exists():
        return _result("config_valid", False, f"Config file not found: {config_path}", "critical")
    if not server_url:
        return _result("config_valid", False, "No server_url configured. Agent/Gateway will use the default localhost URL.", "critical")
    if not config_path.suffix.lower() == ".json":
        return _result("config_valid", False, f"Config file should be JSON: {config_path}", "warning")
    return _result("config_valid", True, f"Configuration valid. Server: {server_url}")


def _check_dns_resolution(server_url: str | None) -> PreflightResult:
    if not server_url:
        return _result("dns_resolution", False, "No server URL configured; DNS not checked.", "warning")
    parsed = urlparse(server_url)
    hostname = (parsed.hostname or "").strip()
    if not hostname:
        return _result("dns_resolution", False, "Server URL has no hostname.", "warning")
    if hostname in {"127.0.0.1", "localhost", "::1"}:
        return _result("dns_resolution", True, f"Local hostname '{hostname}' does not require external DNS.")
    try:
        ip = gethostbyname(hostname)
        return _result("dns_resolution", True, f"Resolved {hostname} to {ip}.")
    except Exception as exc:
        return _result("dns_resolution", False, f"Unable to resolve {hostname}: {exc}", "warning")


def _check_server_reachable(server_url: str | None) -> PreflightResult:
    if not server_url:
        return _result("server_reachable", False, "No server URL configured.", "critical")
    if requests is None:
        return _result("server_reachable", False, "requests library not available for connectivity check", "warning")

    base_url = server_url.rstrip("/")
    if "/api/v1/collect" in base_url:
        base_url = base_url.split("/api/v1/collect")[0]
    if not base_url.endswith("/api/v1"):
        base_url = base_url.rstrip("/") + "/api/v1"
    ping_url = base_url + "/ping"
    try:
        response = requests.get(ping_url, timeout=5)
        if response.ok:
            return _result("server_reachable", True, f"Server responded OK at {ping_url}.")
        return _result("server_reachable", False, f"Server returned HTTP {response.status_code} from {ping_url}", "critical")
    except Exception as exc:
        return _result("server_reachable", False, f"Cannot reach server at {ping_url}: {exc}", "critical")


def _check_server_target(server_url: str | None) -> PreflightResult:
    if not server_url:
        return _result("server_target", False, "No server URL configured.", "critical")
    parsed = urlparse(server_url)
    hostname = (parsed.hostname or "").strip().lower()
    if hostname in {"127.0.0.1", "localhost", "::1"}:
        return _result(
            "server_target",
            False,
            "Server URL still targets localhost. Use the LAN/server IP on remote agents and gateways.",
            "critical",
        )
    return _result("server_target", True, f"Server target set to {hostname}.")


def _check_interface_available(interface: str | None) -> PreflightResult:
    if not interface:
        return _result("interface_available", True, "No specific interface configured; will use default capture selection.")
    try:
        import psutil
    except Exception:
        return _result("interface_available", False, "psutil not available; cannot verify interface existence", "warning")
    interfaces = set(psutil.net_if_addrs().keys())
    if interface in interfaces:
        return _result("interface_available", True, f"Interface '{interface}' is available.")
    return _result("interface_available", False, f"Interface '{interface}' was not found on this host.", "critical")


def _check_permissions(role: str) -> PreflightResult:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", 0))
        finally:
            sock.close()
        return _result("capture_permissions", True, f"{role.title()} capture permissions look usable for startup diagnostics.")
    except PermissionError as exc:
        return _result("capture_permissions", False, f"Permission denied while validating capture permissions: {exc}", "critical")
    except Exception as exc:
        return _result("capture_permissions", False, f"Unable to validate capture permissions: {exc}", "warning")


def run_preflight(
    *,
    role: str,
    config_path: str | Path,
    server_url: str | None,
    interface: str | None = None,
) -> list[PreflightResult]:
    config_path = Path(config_path)
    results = [
        _check_config_valid(config_path, server_url),
        _check_server_target(server_url),
        _check_dns_resolution(server_url),
        _check_server_reachable(server_url),
        _check_interface_available(interface),
        _check_permissions(role),
    ]
    return results


def print_preflight_report(results: list[PreflightResult], *, title: str | None = None) -> None:
    header = title or "NetVisor Preflight"
    print(f"\n=== {header} ===")
    for result in results:
        status = "PASS" if result.passed else result.severity.upper()
        print(f"[{status}] {result.check_name}: {result.message}")
    critical_failures = [result for result in results if not result.passed and result.severity == "critical"]
    warnings = [result for result in results if not result.passed and result.severity == "warning"]
    print(f"Summary: {len(results) - len(critical_failures) - len(warnings)} passed, {len(warnings)} warnings, {len(critical_failures)} critical failures")


def preflight_exit_code(results: list[PreflightResult]) -> int:
    critical_failures = [result for result in results if not result.passed and result.severity == "critical"]
    return 1 if critical_failures else 0


def serialize_preflight_results(results: list[PreflightResult]) -> str:
    return json.dumps([result.__dict__ for result in results], indent=2, sort_keys=True)
