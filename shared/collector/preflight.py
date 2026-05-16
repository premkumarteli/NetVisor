"""
Startup preflight checks for agent and gateway collectors.

Validates configuration, network connectivity, capture permissions, and
interface availability before the collector starts capturing traffic.

Usage:
    python run_agent.py --preflight
    python run_gateway.py --preflight

Or programmatically:
    from shared.collector.preflight import run_preflight
    results = run_preflight(role="agent", config=config, server_url=url)
"""

from __future__ import annotations

import logging
import platform
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from shared.collector.network_scope import build_scope_policy, summarize_scope_policy

try:
    import psutil
except ImportError:  # pragma: no cover - depends on runtime install
    psutil = None

try:
    import requests
except ImportError:  # pragma: no cover - depends on runtime install
    requests = None

logger = logging.getLogger("netvisor.preflight")

# Severity levels
CRITICAL = "critical"  # Agent should not start
WARNING = "warning"    # Agent can start but functionality is limited
INFO = "info"          # Informational


@dataclass
class PreflightResult:
    """Result of a single preflight check."""

    check_name: str
    passed: bool
    message: str
    severity: str = INFO  # critical, warning, info

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] {self.check_name}: {self.message}"


def _check_config_valid(config: Dict, config_path: Optional[Path] = None) -> PreflightResult:
    """Check that the configuration is valid and contains required fields."""
    if config_path and not config_path.exists():
        return PreflightResult(
            check_name="config_file",
            passed=False,
            message=f"Config file not found: {config_path}",
            severity=WARNING,
        )

    server_url = str(config.get("server_url") or "").strip()
    if not server_url:
        return PreflightResult(
            check_name="config_server_url",
            passed=False,
            message="No server_url configured. Agent will use default http://127.0.0.1:8000",
            severity=WARNING,
        )

    return PreflightResult(
        check_name="config_valid",
        passed=True,
        message=f"Configuration valid. Server: {server_url}",
        severity=INFO,
    )


def _check_server_reachable(server_url: str) -> PreflightResult:
    """Check if the backend server is reachable via HTTP."""
    if not server_url:
        return PreflightResult(
            check_name="server_reachable",
            passed=False,
            message="No server URL configured",
            severity=WARNING,
        )

    base_url = server_url.rstrip("/")
    if "/api/v1/collect" in base_url:
        base_url = base_url.split("/api/v1/collect")[0]
    elif base_url.endswith("/api/v1"):
        base_url = base_url.rsplit("/api/v1", 1)[0]

    try:
        if requests is None:
            return PreflightResult(
                check_name="server_reachable",
                passed=False,
                message="requests library not available for connectivity check",
                severity=WARNING,
            )
        response = requests.get(f"{base_url}/ping", timeout=5)
        if response.status_code == 200:
            return PreflightResult(
                check_name="server_reachable",
                passed=True,
                message=f"Server at {base_url} responded OK",
                severity=INFO,
            )
        return PreflightResult(
            check_name="server_reachable",
            passed=False,
            message=f"Server at {base_url} returned HTTP {response.status_code}",
            severity=WARNING,
        )
    except Exception as exc:
        return PreflightResult(
            check_name="server_reachable",
            passed=False,
            message=f"Cannot reach server at {base_url}: {exc}",
            severity=WARNING,
        )


def _check_interface_available(interface: Optional[str]) -> PreflightResult:
    """Check that the configured capture interface exists on the host."""
    if not interface:
        return PreflightResult(
            check_name="capture_interface",
            passed=True,
            message="No specific interface configured; will use default",
            severity=INFO,
        )

    try:
        if psutil is None:
            return PreflightResult(
                check_name="capture_interface",
                passed=False,
                message="psutil not available; cannot verify interface existence",
                severity=WARNING,
            )
        available = psutil.net_if_addrs()
        if interface in available:
            return PreflightResult(
                check_name="capture_interface",
                passed=True,
                message=f"Interface '{interface}' is available",
                severity=INFO,
            )
        available_names = ", ".join(sorted(available.keys())[:10])
        return PreflightResult(
            check_name="capture_interface",
            passed=False,
            message=f"Interface '{interface}' not found. Available: {available_names}",
            severity=CRITICAL,
        )
    except Exception as exc:
        return PreflightResult(
            check_name="capture_interface",
            passed=False,
            message=f"Cannot verify interface existence: {exc}",
            severity=WARNING,
        )


def _check_capture_permissions() -> PreflightResult:
    """
    Check that the process has sufficient permissions for packet capture.

    On Linux: requires CAP_NET_RAW or root.
    On Windows: requires Npcap/WinPcap driver.
    """
    system = platform.system().lower()

    if system == "linux":
        import os
        if os.geteuid() == 0:
            return PreflightResult(
                check_name="capture_permissions",
                passed=True,
                message="Running as root - capture permissions available",
                severity=INFO,
            )

        # Check for CAP_NET_RAW capability
        try:
            cap_path = Path(f"/proc/{os.getpid()}/status")
            if cap_path.exists():
                content = cap_path.read_text()
                for line in content.splitlines():
                    if line.startswith("CapEff:"):
                        cap_hex = int(line.split(":")[1].strip(), 16)
                        # CAP_NET_RAW is bit 13
                        if cap_hex & (1 << 13):
                            return PreflightResult(
                                check_name="capture_permissions",
                                passed=True,
                                message="CAP_NET_RAW capability detected",
                                severity=INFO,
                            )
        except Exception:
            pass

        return PreflightResult(
            check_name="capture_permissions",
            passed=False,
            message="Not running as root and CAP_NET_RAW not detected. Capture may fail.",
            severity=CRITICAL,
        )

    elif system == "windows":
        # On Windows, check if Npcap is installed by looking for npcap DLL
        try:
            import ctypes
            npcap_path = Path("C:/Windows/System32/Npcap")
            if npcap_path.exists():
                return PreflightResult(
                    check_name="capture_permissions",
                    passed=True,
                    message="Npcap installation detected",
                    severity=INFO,
                )
            # Fallback: try WinPcap
            winpcap_path = Path("C:/Windows/System32/wpcap.dll")
            if winpcap_path.exists():
                return PreflightResult(
                    check_name="capture_permissions",
                    passed=True,
                    message="WinPcap installation detected",
                    severity=INFO,
                )
            return PreflightResult(
                check_name="capture_permissions",
                passed=False,
                message="Neither Npcap nor WinPcap found. Install Npcap for packet capture.",
                severity=CRITICAL,
            )
        except Exception as exc:
            return PreflightResult(
                check_name="capture_permissions",
                passed=False,
                message=f"Cannot verify capture driver: {exc}",
                severity=WARNING,
            )

    else:
        return PreflightResult(
            check_name="capture_permissions",
            passed=True,
            message=f"Capture permission check not implemented for {system}",
            severity=INFO,
        )


def _check_dns_resolution(server_url: str) -> PreflightResult:
    """Verify DNS resolution works for the server hostname."""
    if not server_url:
        return PreflightResult(
            check_name="dns_resolution",
            passed=True,
            message="No server URL configured; skipping DNS check",
            severity=INFO,
        )

    try:
        from urllib.parse import urlsplit
        parsed = urlsplit(server_url)
        hostname = parsed.hostname
        if not hostname:
            return PreflightResult(
                check_name="dns_resolution",
                passed=False,
                message="Cannot parse hostname from server URL",
                severity=WARNING,
            )

        addr = socket.gethostbyname(hostname)
        return PreflightResult(
            check_name="dns_resolution",
            passed=True,
            message=f"{hostname} resolves to {addr}",
            severity=INFO,
        )
    except socket.gaierror as exc:
        return PreflightResult(
            check_name="dns_resolution",
            passed=False,
            message=f"DNS resolution failed for server hostname: {exc}",
            severity=WARNING,
        )
    except Exception as exc:
        return PreflightResult(
            check_name="dns_resolution",
            passed=False,
            message=f"DNS check error: {exc}",
            severity=WARNING,
        )


def _check_network_scope(role: str, config: Dict) -> PreflightResult:
    """Validate collector network scope and ignore configuration."""
    policy = build_scope_policy(role=role, config=config)
    invalid = list(policy.invalid_networks) + list(policy.invalid_ips)
    if invalid:
        return PreflightResult(
            check_name="network_scope",
            passed=False,
            message=f"Invalid scope or ignore entries: {', '.join(invalid)}",
            severity=WARNING,
        )

    return PreflightResult(
        check_name="network_scope",
        passed=True,
        message=summarize_scope_policy(policy),
        severity=INFO,
    )


def run_preflight(
    *,
    role: str = "agent",
    config: Optional[Dict] = None,
    config_path: Optional[Path] = None,
    server_url: Optional[str] = None,
    interface: Optional[str] = None,
) -> List[PreflightResult]:
    """
    Run all preflight checks and return structured results.

    Args:
        role: "agent" or "gateway"
        config: Parsed config dict
        config_path: Path to config file (for existence check)
        server_url: Server URL to check connectivity
        interface: Capture interface name to validate
    """
    config = config or {}
    effective_server_url = server_url or str(config.get("server_url") or "").strip()

    results: List[PreflightResult] = []

    results.append(_check_config_valid(config, config_path))
    results.append(_check_dns_resolution(effective_server_url))
    results.append(_check_server_reachable(effective_server_url))
    results.append(_check_interface_available(interface))
    results.append(_check_capture_permissions())
    results.append(_check_network_scope(role, config))

    return results


def print_preflight_report(results: List[PreflightResult], *, role: str = "agent") -> bool:
    """
    Print a colored preflight report table.

    Returns True if no critical checks failed.
    """
    try:
        from colorama import Fore, Style
    except ImportError:
        Fore = type("Fore", (), {"GREEN": "", "RED": "", "YELLOW": "", "CYAN": "", "RESET": ""})()
        Style = type("Style", (), {"RESET_ALL": "", "BRIGHT": ""})()

    title = f"NetVisor {role.capitalize()} Preflight Report"
    print(f"\n{Style.BRIGHT}{Fore.CYAN}{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}{Style.RESET_ALL}\n")

    critical_failures = 0
    warnings = 0

    for result in results:
        if result.passed:
            icon = f"{Fore.GREEN}OK{Style.RESET_ALL}"
        elif result.severity == CRITICAL:
            icon = f"{Fore.RED}FAIL{Style.RESET_ALL}"
            critical_failures += 1
        else:
            icon = f"{Fore.YELLOW}!{Style.RESET_ALL}"
            warnings += 1

        severity_label = f" [{result.severity.upper()}]" if not result.passed else ""
        print(f"  {icon}  {result.check_name:<25} {result.message}{severity_label}")

    print()
    if critical_failures:
        print(f"  {Fore.RED}{Style.BRIGHT}RESULT: {critical_failures} critical failure(s). {role.capitalize()} may not function correctly.{Style.RESET_ALL}")
    elif warnings:
        print(f"  {Fore.YELLOW}{Style.BRIGHT}RESULT: All critical checks passed. {warnings} warning(s).{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}{Style.BRIGHT}RESULT: All checks passed. {role.capitalize()} is ready to start.{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")

    return critical_failures == 0
