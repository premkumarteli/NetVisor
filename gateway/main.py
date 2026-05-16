from __future__ import annotations

import argparse
import json
import os
import queue
import requests
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from colorama import Fore, Style

from shared.collector import (
    DomainHintCache,
    FlowManager,
    FlowSummary,
    PacketObservation,
    build_capture_backend,
    build_scope_policy,
    DiskBackedBuffer,
    compute_machine_fingerprint,
)
from shared.collector.health import CollectorHealthReport
from shared.collector.preflight import run_preflight, print_preflight_report

from .security.transport import GatewayApiClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GATEWAY_RUNTIME_DIR = PROJECT_ROOT / "runtime" / "gateway"
GATEWAY_SECURITY_STATE = GATEWAY_RUNTIME_DIR / "security" / "gateway_transport_state.secure"


class GatewayCollector:
    def __init__(self, *, start_background_workers: bool = True) -> None:
        base_url = os.getenv("NETVISOR_SERVER_URL", "http://127.0.0.1:8000").rstrip("/")
        if "/api/v1" in base_url:
            base_url = base_url.split("/api/v1")[0]

        self.gateway_id = self._init_gateway_id()
        self.organization_id = (
            os.getenv("NETVISOR_ORGANIZATION_ID")
            or os.getenv("NETVISOR_DEFAULT_ORGANIZATION_ID")
            or "default-org-id"
        )
        self.gateway_flows_url = f"{base_url}/api/v1/gateway/flows/batch"
        self.register_url = f"{base_url}/api/v1/gateway/register"
        self.heartbeat_url = f"{base_url}/api/v1/gateway/heartbeat"
        self.rotate_credential_url = f"{base_url}/api/v1/gateway/rotate-credential"
        self.capture_mode = os.getenv("NETVISOR_GATEWAY_CAPTURE_MODE", "promiscuous")
        self.heartbeat_interval = int(os.getenv("NETVISOR_GATEWAY_HEARTBEAT_SECONDS", "10"))
        self.capture_interface = (
            os.getenv("NETVISOR_GATEWAY_CAPTURE_INTERFACE")
            or os.getenv("NETVISOR_CAPTURE_INTERFACE")
            or ""
        ).strip() or None
        self.capture_backend_name = (
            os.getenv("NETVISOR_GATEWAY_CAPTURE_BACKEND")
            or os.getenv("NETVISOR_CAPTURE_BACKEND")
            or "auto"
        ).strip() or "auto"
        self.bootstrap_api_key = str(os.getenv("GATEWAY_API_KEY", "") or "")
        self.is_running = True
        
        buffer_max_mb = int(os.getenv("NETVISOR_BUFFER_MAX_MB", "50"))
        self.buffer = DiskBackedBuffer(
            db_path=GATEWAY_RUNTIME_DIR / "buffer.db",
            max_memory=10000,
            max_disk_mb=buffer_max_mb
        )
        self.domain_cache = DomainHintCache()
        self.scope_policy = build_scope_policy(role="gateway", config={}, local_ip=None)
        self.client = GatewayApiClient(
            state_path=GATEWAY_SECURITY_STATE,
            bootstrap_api_key=self.bootstrap_api_key,
            initial_pins=self._load_initial_pins(),
        )
        self._last_enrollment_warning = None
        self._background_workers_enabled = bool(start_background_workers)

        # Upload health tracking (Phase 1A)
        self._upload_failures: int = 0
        self._upload_successes: int = 0
        self._consecutive_upload_failures: int = 0
        self._last_upload_time: str | None = None
        self._last_upload_error: str | None = None

        self.flow_manager = FlowManager(
            agent_id=self.gateway_id,
            organization_id=self.organization_id,
            on_flow_expired=self._on_flow_expired,
            source_type="gateway",
            metadata_only=True,
            flush_interval=float(os.getenv("NETVISOR_FLOW_FLUSH_INTERVAL_SECONDS", "5")),
            cleanup_interval=float(os.getenv("NETVISOR_FLOW_CLEANUP_INTERVAL_SECONDS", "5")),
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
            threading.Thread(target=self._upload_worker, daemon=True).start()
            threading.Thread(target=self._heartbeat_worker, daemon=True).start()
        else:
            print(f"{Fore.YELLOW}[!] Gateway background workers disabled for probe mode.")

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

    def _registration_payload(self) -> dict:
        return {
            "gateway_id": self.gateway_id,
            "organization_id": self.organization_id,
            "hostname": socket.gethostname(),
            "capture_mode": self.capture_mode,
            "capture_health": self.capture_backend.status_snapshot(),
            "time": datetime.now(timezone.utc).isoformat(),
            "machine_fingerprint": compute_machine_fingerprint(self.organization_id),
        }

    def _apply_server_metadata(self, payload: dict | None) -> None:
        if not isinstance(payload, dict):
            return
        organization_id = str(payload.get("organization_id") or "").strip()
        if organization_id:
            self.organization_id = organization_id
            self.flow_manager.organization_id = organization_id

    def _upload_health_snapshot(self) -> dict:
        """Get upload health metrics for heartbeat reporting."""
        return {
            "upload_failures": self._upload_failures,
            "upload_successes": self._upload_successes,
            "last_upload_time": self._last_upload_time,
            "last_upload_error": self._last_upload_error,
            "queue_depth": self.buffer.pending_count,
            "consecutive_failures": self._consecutive_upload_failures,
            "buffer_disk_usage_bytes": self.buffer.disk_usage_bytes,
        }

    def _build_collector_health(self) -> dict:
        """Build a consolidated collector health report."""
        report = CollectorHealthReport.build(
            capture_snapshot=self.capture_backend.status_snapshot(),
            upload_snapshot=self._upload_health_snapshot(),
            flow_snapshot=self._flow_health_snapshot(),
        )
        return report.to_dict()

    def _flow_health_snapshot(self) -> dict:
        snapshot = self.flow_manager.status_snapshot()
        snapshot["network_scope"] = self.scope_policy.status_snapshot()
        return snapshot

    def status_snapshot(self) -> dict:
        return {
            "gateway_id": self.gateway_id,
            "organization_id": self.organization_id,
            "capture_mode": self.capture_mode,
            "heartbeat_interval_seconds": self.heartbeat_interval,
            "running": self.is_running,
            "upload_queue_depth": self.buffer.pending_count,
            "flow_manager": self.flow_manager.status_snapshot(),
            "network_scope": self.scope_policy.status_snapshot(),
            "capture": self.capture_backend.status_snapshot(),
            "transport": self.client.status_snapshot(),
            "background_workers_enabled": self._background_workers_enabled,
            "collector_health": self._build_collector_health(),
        }

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
                    payload = self._registration_payload()
                    payload["collector_health"] = self._build_collector_health()
                    response = self.client.request("POST", self.heartbeat_url, json_body=payload, timeout=5)
                    response.raise_for_status()
                    self._apply_server_metadata(response.json())
            except requests.HTTPError as exc:
                if exc.response.status_code in {403, 409}:
                    try:
                        err_payload = exc.response.json()
                        status_reason = str(err_payload.get("enrollment_status") or err_payload.get("reason") or "").strip().lower()
                    except ValueError:
                        status_reason = ""
                    
                    if status_reason in {"credential_expired", "credential_rotated", "unknown_credential"}:
                        print(f"{Fore.YELLOW}[!] Gateway heartbeat returned 403 expired credential. Triggering re-enrollment.")
                        self._ensure_enrolled(force_reenroll=True)
                    elif status_reason in {"revoked", "wrong_organization"}:
                        print(f"{Fore.RED}[!] Gateway access revoked or invalid ({status_reason}). Stopping.")
                        self.stop()
                    elif status_reason == "pending_review":
                        print(f"{Fore.YELLOW}[!] Gateway pending review. Pausing heartbeat.")
                    else:
                        print(f"{Fore.YELLOW}[!] Gateway heartbeat 403: {status_reason}")
                else:
                    print(f"{Fore.YELLOW}[!] Gateway heartbeat failed HTTP error: {exc}")
            except Exception as exc:
                print(f"{Fore.YELLOW}[!] Gateway heartbeat failed: {exc}")
            time.sleep(self.heartbeat_interval)

    def _on_flow_expired(self, summary: FlowSummary) -> None:
        payload = dict(summary.__dict__)
        payload["organization_id"] = self.organization_id
        payload["source_type"] = "gateway"
        payload["metadata_only"] = True
        if not self.buffer.enqueue(payload):
            print(f"{Fore.YELLOW}[!] Gateway upload buffer failed to enqueue, dropping flow")

    def _upload_worker(self) -> None:
        batch: list[dict] = []
        last_send = time.time()

        while self.is_running:
            try:
                if self._consecutive_upload_failures > 0:
                    backoff = min(2 ** self._consecutive_upload_failures, 30)
                    time.sleep(backoff)

                records = self.buffer.drain(batch_size=20 - len(batch))
                if records:
                    batch.extend(records)
                else:
                    time.sleep(1.0)

                if len(batch) >= 20 or (time.time() - last_send > 5 and batch):
                    if not self._ensure_enrolled():
                        self.buffer.requeue_front(batch)
                        batch = []
                        time.sleep(2)
                        continue

                    try:
                        response = self.client.request("POST", self.gateway_flows_url, json_body=batch, timeout=10)
                        response.raise_for_status()
                        self._apply_server_metadata(response.json())
                        self._upload_successes += 1
                        self._consecutive_upload_failures = 0
                        self._last_upload_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                        self._last_upload_error = None
                        batch = []
                        last_send = time.time()
                    except requests.HTTPError as exc:
                        if exc.response.status_code in {403, 409}:
                            try:
                                err_payload = exc.response.json()
                                status_reason = str(err_payload.get("enrollment_status") or err_payload.get("reason") or "").strip().lower()
                            except ValueError:
                                status_reason = ""
                            if status_reason in {"credential_expired", "credential_rotated", "unknown_credential"}:
                                print(f"{Fore.YELLOW}[!] Gateway flow upload returned 403 expired credential. Triggering re-enrollment.")
                                self._ensure_enrolled(force_reenroll=True)
                            elif status_reason in {"revoked", "wrong_organization"}:
                                print(f"{Fore.RED}[!] Gateway access revoked or invalid ({status_reason}). Stopping.")
                                self.stop()
                        
                        self._upload_failures += 1
                        self._consecutive_upload_failures += 1
                        self._last_upload_error = str(exc)
                        self.buffer.requeue_front(batch)
                        batch = []
                        print(f"{Fore.YELLOW}[!] Gateway flow upload failed HTTP error: {exc}")
                        time.sleep(2)
                    except Exception as exc:
                        self._upload_failures += 1
                        self._consecutive_upload_failures += 1
                        self._last_upload_error = str(exc)
                        self.buffer.requeue_front(batch)
                        batch = []
                        print(f"{Fore.YELLOW}[!] Gateway flow upload failed: {exc}")
                        time.sleep(2)
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

        decision = self.scope_policy.should_accept_observation(observation)
        if not decision.accepted:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "Gateway dropped packet (%s): %s -> %s",
                    decision.reason,
                    observation.src_ip,
                    observation.dst_ip,
                )
            return False

        if observation.domain and logger.isEnabledFor(logging.DEBUG):
            logger.debug("Gateway observed domain %s -> %s", observation.src_ip, observation.domain)

        self.flow_manager.update_from_observation(observation)
        return True

    def start(self, timeout: int | None = None) -> None:
        print(f"{Fore.BLUE}[*] NetVisor Gateway Starting...")
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
        if hasattr(self, "buffer"):
            self.buffer.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="NetVisor Gateway")
    parser.add_argument("--health-check", action="store_true", help="Print a startup health snapshot and exit.")
    parser.add_argument("--reset-enrollment", action="store_true", help="Clear stored signed credentials and exit.")
    parser.add_argument("--preflight", action="store_true", help="Run preflight checks, print report, and exit.")
    parser.add_argument("--timeout", type=int, default=None, help="Packet sniff timeout in seconds.")
    args = parser.parse_args()

    # --preflight: run checks, print colored table, exit
    if args.preflight:
        server_url = os.getenv("NETVISOR_SERVER_URL", "http://127.0.0.1:8000").rstrip("/")
        if "/api/v1" in server_url:
            server_url = server_url.split("/api/v1")[0]
        interface = (
            os.getenv("NETVISOR_GATEWAY_CAPTURE_INTERFACE")
            or os.getenv("NETVISOR_CAPTURE_INTERFACE")
            or ""
        ).strip() or None
        results = run_preflight(
            role="gateway",
            config={"server_url": server_url},
            server_url=server_url,
            interface=interface,
        )
        all_ok = print_preflight_report(results, role="gateway")
        sys.exit(0 if all_ok else 1)

    if args.health_check or args.reset_enrollment:
        collector = GatewayCollector(start_background_workers=False)
        if args.reset_enrollment:
            collector.client.reset_enrollment()
        snapshot = collector.status_snapshot()
        snapshot["ready"] = bool(collector.client.status_snapshot().get("has_credentials"))
        snapshot["enrollment_required"] = not snapshot["ready"]
        print(json.dumps(snapshot, indent=2, sort_keys=True))
        sys.exit(0)

    # Normal startup: run preflight as non-blocking diagnostics
    try:
        server_url = os.getenv("NETVISOR_SERVER_URL", "http://127.0.0.1:8000").rstrip("/")
        if "/api/v1" in server_url:
            server_url = server_url.split("/api/v1")[0]
        interface = (
            os.getenv("NETVISOR_GATEWAY_CAPTURE_INTERFACE")
            or os.getenv("NETVISOR_CAPTURE_INTERFACE")
            or ""
        ).strip() or None
        results = run_preflight(
            role="gateway",
            config={"server_url": server_url},
            server_url=server_url,
            interface=interface,
        )
        print_preflight_report(results, role="gateway")
    except Exception as exc:
        import logging
        logging.getLogger("netvisor.gateway").warning("Preflight checks failed to run: %s", exc)

    collector = GatewayCollector()
    try:
        collector.start(timeout=args.timeout)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Shutting down NetVisor Gateway...{Style.RESET_ALL}")
    finally:
        collector.stop()


if __name__ == "__main__":
    main()
