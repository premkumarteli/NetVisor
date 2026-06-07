from __future__ import annotations

import argparse
import logging
import ipaddress
import json
import os
import platform
import queue
import socket
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from colorama import Fore, Style

from agent.device_detector import DeviceDetector
from shared.collector import (
    DomainHintCache,
    FlowManager,
    FlowSummary,
    PacketObservation,
    build_capture_backend,
    print_preflight_report,
    run_preflight,
    serialize_preflight_results,
)

from .security.transport import GatewayApiClient

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GATEWAY_RUNTIME_DIR = PROJECT_ROOT / "runtime" / "gateway"
GATEWAY_SECURITY_STATE = GATEWAY_RUNTIME_DIR / "security" / "gateway_transport_state.secure"


def _windows_capture_interfaces() -> list[dict]:
    if platform.system().lower() != "windows":
        return []
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore
    except Exception:
        return []

    interfaces: list[dict] = []
    for item in get_windows_if_list():
        guid = str(item.get("guid") or "").strip()
        capture_name = rf"\Device\NPF_{guid}" if guid.startswith("{") and guid.endswith("}") else guid
        ips = [str(ip) for ip in item.get("ips") or []]
        interfaces.append(
            {
                "name": str(item.get("name") or "").strip(),
                "description": str(item.get("description") or "").strip(),
                "guid": guid,
                "capture_name": capture_name,
                "ips": ips,
            }
        )
    return interfaces


def _valid_ipv4_addresses(ips: list[str]) -> list[ipaddress.IPv4Address]:
    addresses: list[ipaddress.IPv4Address] = []
    for raw_ip in ips:
        try:
            parsed = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if not isinstance(parsed, ipaddress.IPv4Address):
            continue
        if parsed.is_loopback or parsed.is_link_local:
            continue
        addresses.append(parsed)
    return addresses


def list_gateway_capture_interfaces() -> list[dict]:
    rows = []
    for iface in _windows_capture_interfaces():
        ipv4_addresses = [str(ip) for ip in _valid_ipv4_addresses(iface["ips"])]
        rows.append(
            {
                "name": iface["name"],
                "description": iface["description"],
                "capture_interface": iface["capture_name"],
                "ipv4": ipv4_addresses,
                "hotspot_candidate": any(ip.startswith("192.168.137.") for ip in ipv4_addresses),
            }
        )
    return rows


def _resolve_gateway_capture_interface(configured_interface: str | None) -> tuple[str | None, str]:
    if configured_interface:
        return configured_interface, "configured"

    if platform.system().lower() != "windows":
        return None, "default"

    requested_subnet = os.getenv("NETVISOR_GATEWAY_CAPTURE_SUBNET", "192.168.137.0/24").strip()
    try:
        hotspot_network = ipaddress.ip_network(requested_subnet, strict=False)
    except ValueError:
        hotspot_network = ipaddress.ip_network("192.168.137.0/24", strict=False)

    candidates = _windows_capture_interfaces()
    for iface in candidates:
        for ip in _valid_ipv4_addresses(iface["ips"]):
            if ip in hotspot_network:
                return iface["capture_name"], f"auto-hotspot-subnet:{hotspot_network}"

    for iface in candidates:
        description = iface["description"].lower()
        name = iface["name"].lower()
        if "wi-fi direct virtual adapter" in description or "local area connection*" in name:
            ipv4_addresses = _valid_ipv4_addresses(iface["ips"])
            if ipv4_addresses:
                return iface["capture_name"], "auto-wifi-direct"

    return None, "default"


class GatewayCollector:
    def __init__(self, *, start_background_workers: bool = True) -> None:
        base_url = os.getenv("NETVISOR_SERVER_URL", "http://127.0.0.1:8000").rstrip("/")
        if "/api/v1" in base_url:
            base_url = base_url.split("/api/v1")[0]

        self.server_url = base_url

        self.gateway_id = self._init_gateway_id()
        self.organization_id = (
            os.getenv("NETVISOR_ORGANIZATION_ID")
            or os.getenv("NETVISOR_DEFAULT_ORGANIZATION_ID")
            or "default-org-id"
        )
        self.gateway_flows_url = f"{base_url}/api/v1/gateway/flows/batch"
        self.gateway_devices_url = f"{base_url}/api/v1/gateway/devices/batch"
        self.register_url = f"{base_url}/api/v1/gateway/register"
        self.heartbeat_url = f"{base_url}/api/v1/gateway/heartbeat"
        self.rotate_credential_url = f"{base_url}/api/v1/gateway/rotate-credential"
        self.capture_mode = os.getenv("NETVISOR_GATEWAY_CAPTURE_MODE", "promiscuous")
        self.heartbeat_interval = int(os.getenv("NETVISOR_GATEWAY_HEARTBEAT_SECONDS", "10"))
        self.upload_batch_size = max(int(os.getenv("NETVISOR_GATEWAY_UPLOAD_BATCH_SIZE", "10")), 1)
        self.upload_interval_seconds = max(float(os.getenv("NETVISOR_GATEWAY_UPLOAD_INTERVAL_SECONDS", "1.0")), 0.5)
        self.upload_timeout_seconds = max(float(os.getenv("NETVISOR_GATEWAY_UPLOAD_TIMEOUT_SECONDS", "20")), 1.0)
        self.upload_backoff_max_seconds = max(float(os.getenv("NETVISOR_GATEWAY_UPLOAD_BACKOFF_MAX_SECONDS", "30")), 1.0)
        configured_capture_interface = (
            os.getenv("NETVISOR_GATEWAY_CAPTURE_INTERFACE")
            or os.getenv("NETVISOR_CAPTURE_INTERFACE")
            or ""
        ).strip() or None
        self.capture_interface, self.capture_interface_source = _resolve_gateway_capture_interface(configured_capture_interface)
        self.capture_backend_name = (
            os.getenv("NETVISOR_GATEWAY_CAPTURE_BACKEND")
            or os.getenv("NETVISOR_CAPTURE_BACKEND")
            or "auto"
        ).strip() or "auto"
        self.bootstrap_api_key = str(os.getenv("GATEWAY_API_KEY", "") or "")
        self.is_running = True
        self.upload_q: queue.Queue[dict] = queue.Queue(maxsize=10000)
        self.domain_cache = DomainHintCache()
        self.local_ip = self._capture_interface_ipv4() or self._detect_local_ip()
        self.local_network = self._infer_network(self.local_ip)
        self.device_detector = DeviceDetector(local_ip=self.local_ip)
        if self.local_network:
            self.device_detector.set_network(self.local_network)
            logger.info("Gateway discovery network set to %s", self.local_network)
        else:
            logger.warning("Unable to infer gateway discovery network; falling back to passive ARP cache only.")
        self.discovery_pool = ThreadPoolExecutor(
            max_workers=max(int(os.getenv("NETVISOR_GATEWAY_DISCOVERY_WORKERS", "5")), 1)
        )
        self.client = GatewayApiClient(
            state_path=GATEWAY_SECURITY_STATE,
            bootstrap_api_key=self.bootstrap_api_key,
            initial_pins=self._load_initial_pins(),
        )
        self._last_enrollment_warning = None
        self._background_workers_enabled = bool(start_background_workers)

        self.flow_manager = FlowManager(
            agent_id=self.gateway_id,
            organization_id=self.organization_id,
            on_flow_expired=self._on_flow_expired,
            source_type="gateway",
            metadata_only=True,
            flush_interval=float(
                os.getenv("NETVISOR_GATEWAY_FLOW_FLUSH_INTERVAL_SECONDS")
                or "1.5"
            ),
            cleanup_interval=float(
                os.getenv("NETVISOR_GATEWAY_FLOW_CLEANUP_INTERVAL_SECONDS")
                or "1.0"
            ),
            max_flows=int(os.getenv("NETVISOR_FLOW_MAX_ACTIVE_FLOWS", "50000")),
            start_worker=self._background_workers_enabled,
        )
        self.capture_backend = build_capture_backend(
            role="gateway",
            interface=self.capture_interface,
            requested_backend=self.capture_backend_name,
        )

        if self._background_workers_enabled:
            if not self._ensure_enrolled(initial=True, force_reenroll=not self.client.has_credentials()):
                raise RuntimeError(
                    "Gateway enrollment failed. The gateway requires a valid signed credential before it can continue."
                )
            if self.client.has_credentials():
                print(f"{Fore.GREEN}[+] Gateway registered and enrolled: {self.gateway_id}{Style.RESET_ALL}")
            print("[*] Starting upload worker...")
            threading.Thread(target=self._upload_worker, daemon=True).start()
            print("[*] Starting heartbeat worker...")
            threading.Thread(target=self._heartbeat_worker, daemon=True).start()
            print("[*] Starting gateway discovery worker...")
            threading.Thread(target=self._discovery_worker, daemon=True).start()
        else:
            print(f"{Fore.YELLOW}[!] Gateway background workers disabled for probe mode.")

    def _hardening_findings(self) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        transport_snapshot = self.client.status_snapshot()

        if not self.bootstrap_api_key.strip():
            findings.append(
                {
                    "severity": "critical",
                    "code": "missing_bootstrap_key",
                    "message": "Gateway API bootstrap key is not configured.",
                }
            )

        if self._background_workers_enabled and not self.client.has_credentials():
            findings.append(
                {
                    "severity": "critical",
                    "code": "unenrolled_gateway",
                    "message": "Gateway is not enrolled with signed credentials.",
                }
            )

        if self._background_workers_enabled and not self.capture_interface:
            findings.append(
                {
                    "severity": "critical",
                    "code": "capture_interface_unset",
                    "message": "No capture interface is configured, so the gateway cannot operate safely in production.",
                }
            )

        if self._background_workers_enabled and self.local_network is None:
            findings.append(
                {
                    "severity": "warning",
                    "code": "network_uninferred",
                    "message": "Gateway discovery network could not be inferred automatically.",
                }
            )

        if self._background_workers_enabled and transport_snapshot.get("backend_tls_pin_count", 0) == 0:
            findings.append(
                {
                    "severity": "critical",
                    "code": "missing_tls_pins",
                    "message": "Remote gateway transport has no configured TLS pins.",
                }
            )

        if self.capture_mode.strip().lower() == "promiscuous":
            findings.append(
                {
                    "severity": "warning",
                    "code": "promiscuous_capture_mode",
                    "message": "Promiscuous capture mode is enabled; restrict it if the deployment does not need full L2 observation.",
                }
            )

        return findings

    def _init_gateway_id(self) -> str:
        GATEWAY_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        id_file = GATEWAY_RUNTIME_DIR / "gateway_id.txt"
        if id_file.exists():
            with id_file.open("r", encoding="utf-8") as handle:
                return handle.read().strip()

        gateway_id = f"GATEWAY-{uuid.uuid4().hex[:8].upper()}"
        with id_file.open("w", encoding="utf-8") as handle:
            handle.write(gateway_id)
        return gateway_id

    def _load_initial_pins(self) -> list[dict]:
        raw = str(os.getenv("NETVISOR_BACKEND_TLS_PINS_JSON", "[]") or "[]").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except ValueError:
            print(f"{Fore.YELLOW}[!] Invalid NETVISOR_BACKEND_TLS_PINS_JSON; ignoring seed pins")
            return []
        return parsed if isinstance(parsed, list) else []

    def _capture_interface_ipv4(self) -> str | None:
        capture_interface = str(self.capture_interface or "").strip()
        if not capture_interface:
            return None

        normalized_capture = capture_interface.replace("\\Device\\NPF_", "")
        for iface in _windows_capture_interfaces():
            if iface.get("guid") != normalized_capture and iface.get("capture_name") != capture_interface:
                continue
            addresses = _valid_ipv4_addresses(iface.get("ips") or [])
            if addresses:
                return str(addresses[0])
        return None

    def _detect_local_ip(self) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect(("10.255.255.255", 1))
                return sock.getsockname()[0]
            finally:
                sock.close()
        except Exception:
            return "127.0.0.1"

    def _infer_network(self, ip_value: str | None) -> str | None:
        configured_network = os.getenv("NETVISOR_GATEWAY_DISCOVERY_NETWORK", "").strip()
        if configured_network:
            return configured_network

        if not ip_value:
            return None

        try:
            target_ip = ipaddress.ip_address(ip_value)
        except ValueError:
            return None

        if isinstance(target_ip, ipaddress.IPv4Address) and target_ip.is_private:
            return str(ipaddress.ip_network(f"{ip_value}/24", strict=False))
        return None

    def _registration_payload(self) -> dict:
        return {
            "gateway_id": self.gateway_id,
            "organization_id": self.organization_id,
            "hostname": socket.gethostname(),
            "capture_mode": self.capture_mode,
            "time": datetime.now(timezone.utc).isoformat(),
        }

    def _apply_server_metadata(self, payload: dict | None) -> None:
        if not isinstance(payload, dict):
            return
        organization_id = str(payload.get("organization_id") or "").strip()
        if organization_id:
            self.organization_id = organization_id
            self.flow_manager.organization_id = organization_id

    def status_snapshot(self) -> dict:
        hardening_findings = self._hardening_findings()
        return {
            "gateway_id": self.gateway_id,
            "organization_id": self.organization_id,
            "capture_mode": self.capture_mode,
            "heartbeat_interval_seconds": self.heartbeat_interval,
            "running": self.is_running,
            "upload_queue_depth": self.upload_q.qsize(),
            "flow_manager": self.flow_manager.status_snapshot(),
            "capture": self.capture_backend.status_snapshot(),
            "capture_interface_source": self.capture_interface_source,
            "local_ip": self.local_ip,
            "local_network": self.local_network,
            "transport": self.client.status_snapshot(),
            "background_workers_enabled": self._background_workers_enabled,
            "hardening": {
                "ready": not any(finding["severity"] == "critical" for finding in hardening_findings),
                "finding_count": len(hardening_findings),
                "findings": hardening_findings,
            },
        }

    def _assert_hardening_ready(self) -> None:
        snapshot = self.status_snapshot()
        hardening = snapshot.get("hardening", {})
        if hardening.get("ready"):
            return

        findings = hardening.get("findings") or []
        critical_findings = [finding for finding in findings if finding.get("severity") == "critical"]
        if critical_findings:
            summary = ", ".join(
                f"{finding.get('code')}: {finding.get('message')}" for finding in critical_findings
            )
        else:
            summary = "hardening checks failed"
        raise RuntimeError(f"Gateway hardening check failed: {summary}")

    def _register_gateway(self, *, initial: bool = False, force_reenroll: bool = False) -> bool:
        try:
            payload = self._registration_payload()
            payload["reenroll"] = bool(force_reenroll)
            response = self.client.bootstrap_post(self.register_url, json_body=payload, timeout=10, reenroll=force_reenroll)
            response.raise_for_status()
            payload = response.json()
            self._apply_server_metadata(payload)
            credentials = payload.get("gateway_credentials")
            if isinstance(credentials, dict) and credentials.get("secret"):
                if force_reenroll:
                    print(f"{Fore.GREEN}[+] Gateway re-enrolled: {self.gateway_id}")
                else:
                    print(f"{Fore.GREEN}[+] Gateway registered and enrolled: {self.gateway_id}")
            else:
                raise RuntimeError(
                    "Gateway registration did not yield signed credentials and no stored credential is available. "
                    "This gateway requires explicit credential rotation or re-enrollment before it can continue."
                )
            return True
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            if message != self._last_enrollment_warning:
                self._last_enrollment_warning = message
                print(f"{Fore.YELLOW}[!] Gateway registration failed: {exc}")
            return False

    def _ensure_enrolled(self, *, initial: bool = False, force_reenroll: bool = False) -> bool:
        retry_delay = 1
        if self.client.has_credentials() and not force_reenroll:
            return True

        while self.is_running:
            should_reenroll = force_reenroll or not self.client.has_credentials()
            if not should_reenroll and self.client.has_credentials():
                return True

            if self._register_gateway(force_reenroll=should_reenroll):
                return self.client.has_credentials()

            if initial:
                initial = False
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 30)
        return False

    def _heartbeat_worker(self) -> None:
        while self.is_running:
            try:
                if self._ensure_enrolled():
                    response = self.client.request("POST", self.heartbeat_url, json_body=self._registration_payload(), timeout=5)
                    response.raise_for_status()
                    self._apply_server_metadata(response.json())
            except Exception as exc:
                print(f"{Fore.YELLOW}[!] Gateway heartbeat failed: {exc}")
            time.sleep(self.heartbeat_interval)

    def _on_flow_expired(self, summary: FlowSummary) -> None:
        payload = dict(summary.__dict__)
        payload["organization_id"] = self.organization_id
        payload["source_type"] = "gateway"
        payload["metadata_only"] = True
        try:
            self.upload_q.put(payload, block=False)
        except queue.Full:
            print(f"{Fore.YELLOW}[!] Gateway upload queue full, dropping flow")

    def _resolve_discovered_device(self, candidate: tuple[str, str]) -> dict:
        ip, mac = candidate
        hostname = self.device_detector.resolve_hostname(ip) or "Unknown"
        vendor = self.device_detector.resolve_vendor(mac)
        active_probe = str(os.getenv("NETVISOR_GATEWAY_ACTIVE_TYPE_PROBE", "false")).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        device_type = self.device_detector.infer_device_type(
            ip,
            mac=mac,
            hostname=hostname,
            active_probe=active_probe,
        )
        confidence = self.device_detector.identity_confidence(
            hostname=hostname,
            mac=mac,
            vendor=vendor,
            device_type=device_type,
        )
        evidence_sources = ["arp"]
        if hostname != "Unknown":
            evidence_sources.append("hostname")
        if vendor != "Unknown":
            evidence_sources.append("oui")
        if device_type != "Unknown":
            evidence_sources.append("type_hint")

        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "device_type": device_type,
            "os_family": "Unknown",
            "is_online": True,
            "organization_id": self.organization_id,
            "gateway_id": self.gateway_id,
            "confidence": confidence,
            "evidence_sources": evidence_sources,
            "last_seen": datetime.now(timezone.utc).isoformat(),
        }

    def _sync_discovered_devices(self, devices: list[dict]) -> None:
        if not devices:
            return
        if not self._ensure_enrolled():
            return

        try:
            response = self.client.request(
                "POST",
                self.gateway_devices_url,
                json_body=devices,
                timeout=10,
            )
            response.raise_for_status()
            self._apply_server_metadata(response.json())
        except Exception as exc:
            print(f"{Fore.YELLOW}[!] Gateway device sync failed: {exc}")

    def _discovery_worker(self) -> None:
        interval = max(int(os.getenv("NETVISOR_GATEWAY_DISCOVERY_SECONDS", "15")), 5)
        while self.is_running:
            try:
                arp_data = self.device_detector.collect_arp_candidates(self.local_network)
                candidates: list[tuple[str, str]] = []
                for ip, mac in arp_data.items():
                    try:
                        if not ipaddress.ip_address(ip).is_private:
                            continue
                    except ValueError:
                        continue
                    if ip == self.local_ip:
                        continue
                    candidates.append((ip, mac))

                futures = [self.discovery_pool.submit(self._resolve_discovered_device, candidate) for candidate in candidates]
                discovered_payloads: list[dict] = []
                for future in as_completed(futures):
                    try:
                        discovered_payloads.append(future.result())
                    except Exception as exc:
                        logger.warning("Gateway device resolve failed: %s", exc)

                self._sync_discovered_devices(discovered_payloads)
            except Exception as exc:
                logger.warning("Gateway discovery cycle failed: %s", exc)
            time.sleep(interval)

    def _upload_worker(self) -> None:
        batch: list[dict] = []
        last_send = time.time()
        failure_count = 0

        while self.is_running:
            try:
                try:
                    record = self.upload_q.get(timeout=1.0)
                    batch.append(record)
                    self.upload_q.task_done()
                except queue.Empty:
                    pass

                should_send = len(batch) >= self.upload_batch_size or (
                    batch and time.time() - last_send > self.upload_interval_seconds
                )
                if should_send:
                    if not self._ensure_enrolled():
                        time.sleep(2)
                        continue

                    try:
                        response = self.client.request(
                            "POST",
                            self.gateway_flows_url,
                            json_body=batch,
                            timeout=self.upload_timeout_seconds,
                        )
                        response.raise_for_status()
                        self._apply_server_metadata(response.json())
                        batch = []
                        failure_count = 0
                        last_send = time.time()
                    except Exception as exc:
                        failure_count += 1
                        status_code = getattr(getattr(exc, "response", None), "status_code", None)
                        delay = min(self.upload_backoff_max_seconds, 2 ** min(failure_count, 5))
                        if status_code == 429:
                            delay = max(delay, min(self.upload_backoff_max_seconds, 15))
                        last_send = time.time()
                        print(f"{Fore.YELLOW}[!] Gateway flow upload failed: {exc}. Retrying in {delay:.1f}s")
                        time.sleep(delay)
            except Exception:
                pass

    def process_packet(self, packet) -> bool:
        observation = PacketObservation.from_packet(
            packet,
            source_type="gateway",
            metadata_only=True,
            domain_cache=self.domain_cache,
        )
        if observation is None:
            return False

        if observation.domain and logger.isEnabledFor(logging.DEBUG):
            logger.debug("Gateway observed domain %s -> %s", observation.src_ip, observation.domain)

        self.flow_manager.update_from_observation(observation)
        return True

    def start(self, timeout: int | None = None) -> None:
        self._assert_hardening_ready()
        print(f"{Fore.BLUE}[*] NetVisor Gateway Starting...")
        if self.capture_interface:
            print(f"{Fore.BLUE}[*] Gateway capture interface: {self.capture_interface} ({self.capture_interface_source})")
        else:
            print(f"{Fore.RED}[!] Gateway capture interface not set; refusing to continue in production mode.")
        success, error = self.capture_backend.start(self.process_packet, timeout=timeout)
        if not success and self.capture_backend.backend_name != "scapy":
            print(f"{Fore.YELLOW}[!] Primary capture backend failed: {error}. Falling back to Scapy.")
            self.capture_backend.stop()
            self.capture_backend = build_capture_backend(
                role="gateway",
                interface=self.capture_interface,
                requested_backend="scapy",
            )
            success, error = self.capture_backend.start(self.process_packet, timeout=timeout)
        if not success and error:
            print(f"{Fore.YELLOW}[!] Gateway capture backend failed: {error}")

    def stop(self) -> None:
        self.is_running = False
        if hasattr(self, "capture_backend"):
            self.capture_backend.stop()
        self.flow_manager.stop()
        if hasattr(self, "discovery_pool"):
            self.discovery_pool.shutdown(wait=False, cancel_futures=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="NetVisor Gateway")
    parser.add_argument("--health-check", action="store_true", help="Print a startup health snapshot and exit.")
    parser.add_argument("--preflight", action="store_true", help="Run startup preflight checks and exit.")
    parser.add_argument("--list-interfaces", action="store_true", help="List gateway capture interfaces and exit.")
    parser.add_argument("--reset-enrollment", action="store_true", help="Clear stored signed credentials and exit.")
    parser.add_argument("--timeout", type=int, default=None, help="Packet sniff timeout in seconds.")
    args = parser.parse_args()

    if args.list_interfaces:
        print(json.dumps(list_gateway_capture_interfaces(), indent=2, sort_keys=True))
        sys.exit(0)

    if args.preflight:
        collector = GatewayCollector(start_background_workers=False)
        results = run_preflight(
            role="gateway",
            config_path=PROJECT_ROOT / "config" / "gateway.json",
            server_url=os.getenv("NETVISOR_SERVER_URL", "http://127.0.0.1:8000"),
            interface=collector.capture_interface,
        )
        print_preflight_report(results, title="NetVisor Gateway Preflight")
        print(serialize_preflight_results(results))
        sys.exit(0 if all(result.passed or result.severity != "critical" for result in results) else 1)

    if args.health_check or args.reset_enrollment:
        collector = GatewayCollector(start_background_workers=False)
        if args.reset_enrollment:
            collector.client.reset_enrollment()
        snapshot = collector.status_snapshot()
        snapshot["ready"] = bool(snapshot.get("hardening", {}).get("ready")) and bool(
            collector.client.status_snapshot().get("has_credentials")
        )
        snapshot["enrollment_required"] = not bool(collector.client.status_snapshot().get("has_credentials"))
        print(json.dumps(snapshot, indent=2, sort_keys=True))
        sys.exit(0)

    collector = GatewayCollector()
    try:
        collector.start(timeout=args.timeout)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Shutting down NetVisor Gateway...{Style.RESET_ALL}")
    finally:
        collector.stop()


if __name__ == "__main__":
    main()
