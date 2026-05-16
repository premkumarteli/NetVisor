import argparse
import json
import logging
import os
import socket
import sys
import threading
import uuid
from pathlib import Path
from colorama import Fore, Style

from agent.capture import CaptureManager
from agent.device_detector import DeviceDetector
from agent.discovery import DeviceInventory, DiscoveryManager
from agent.enrollment import EnrollmentManager
from agent.heartbeat import HeartbeatManager
from agent.security import AgentApiClient
from agent.upload import UploadManager
from agent.config_manager import ConfigManager
from agent.telemetry import TelemetryManager
from shared.collector import (
    DomainHintCache,
    FlowManager,
    FlowSummary,
    PacketObservation,
    build_scope_policy,
)
from shared.collector.preflight import run_preflight, print_preflight_report

try:
    from agent.dpi import WebInspectionController
except ImportError as e:
    logging.warning(f"DPI module failed to import: {e}. Running in degraded mode without DPI.")
    WebInspectionController = None

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "agent.json"
AGENT_RUNTIME_DIR = PROJECT_ROOT / "runtime" / "agent"


# =========================================================
# MAIN AGENT
# =========================================================

class NetworkAgent:

    def __init__(self, config_path=DEFAULT_CONFIG_PATH, *, start_background_workers: bool = True):
        self.config = self._load_config(config_path)
        self.hostname = socket.gethostname()
        self.agent_version = "v3.0-hybrid"
        self._background_workers_enabled = bool(start_background_workers)
        self._workers_started = False
        self.is_running = True

        # Configuration
        self._setup_urls()
        self.agent_id = self._init_agent_id()
        self.organization_id = self._resolve_initial_organization_id()
        self.api_key = os.getenv("AGENT_API_KEY") or self.config.get("api_key", "soc-agent-key-2026")
        self.heartbeat_interval = int(os.getenv("NETVISOR_AGENT_HEARTBEAT_SECONDS", "10"))
        self.web_proxy_port = int(os.getenv("NETVISOR_WEB_PROXY_PORT", "8899"))
        self.web_policy_refresh_seconds = int(os.getenv("NETVISOR_WEB_POLICY_REFRESH_SECONDS", "30"))
        self.capture_interface = (
            os.getenv("NETVISOR_AGENT_CAPTURE_INTERFACE")
            or os.getenv("NETVISOR_CAPTURE_INTERFACE")
            or ""
        ).strip() or None
        self.capture_backend_name = (
            os.getenv("NETVISOR_AGENT_CAPTURE_BACKEND")
            or os.getenv("NETVISOR_CAPTURE_BACKEND")
            or "auto"
        ).strip() or "auto"
        self.verbose = str(os.getenv("NETVISOR_PACKET_TRACE", "false")).strip().lower() in {"1", "true", "yes", "on"}

        # Network detection
        self.local_ip = self._detect_local_ip()
        self.local_mac = self._detect_local_mac()
        self.scope_policy = build_scope_policy(
            role="agent",
            config=self.config,
            local_ip=self.local_ip,
        )

        # Initialize components
        self._init_components()

        if self._background_workers_enabled:
            registration = self.enrollment_manager.register_agent(force_reenroll=not self.api_client.has_credentials())
            if registration and registration.get("organization_id"):
                self._set_organization_id(registration["organization_id"])
            if not self.enrollment_manager.enrollment_pending:
                self._start_operational_workers()
        else:
            logger.info("Agent background workers disabled for probe mode.")

    def _setup_urls(self):
        """Setup API URLs from configuration."""
        url_config = self.config.get("server_url", "http://127.0.0.1:8000")
        base = url_config.rstrip("/")
        if "/api/v1/collect" in base:
            base = base.split("/api/v1/collect")[0]

        self.flow_url = base + "/api/v1/collect/flow/batch"
        self.heartbeat_url = base + "/api/v1/collect/heartbeat"
        self.devices_url = base + "/api/v1/collect/devices/batch"
        self.policy_url = base + "/api/v1/policy"
        self.web_policy_url = base + "/api/v1/collect/web-policy"
        self.web_events_url = base + "/api/v1/collect/web-events/batch"
        self.config_url = base + "/api/v1/collect/config"
        self.telemetry_url = base + "/api/v1/collect/telemetry/batch"

    def _init_components(self):
        """Initialize all agent components."""
        # API client
        self.api_client = AgentApiClient(
            state_path=AGENT_RUNTIME_DIR / "security" / "agent_transport_state.dpapi",
            bootstrap_api_key=self.api_key,
            initial_pins=self._load_initial_backend_pins(),
        )

        # Core components
        self.domain_cache = DomainHintCache()
        self.device_inventory = DeviceInventory(storage_file=AGENT_RUNTIME_DIR / "device_inventory.json", runtime_dir=AGENT_RUNTIME_DIR)
        self.device_detector = DeviceDetector(local_ip=self.local_ip)

        # Flow manager
        self.flow_manager = FlowManager(
            agent_id=self.agent_id,
            organization_id=self.organization_id,
            on_flow_expired=self._on_flow_expired,
            source_type="agent",
            metadata_only=False,
            flush_interval=float(os.getenv("NETVISOR_FLOW_FLUSH_INTERVAL_SECONDS", "5")),
            cleanup_interval=float(os.getenv("NETVISOR_FLOW_CLEANUP_INTERVAL_SECONDS", "5")),
            max_flows=int(os.getenv("NETVISOR_FLOW_MAX_ACTIVE_FLOWS", "50000")),
            start_worker=self._background_workers_enabled,
        )

        # Managers
        self.enrollment_manager = EnrollmentManager(
            agent_id=self.agent_id,
            hostname=self.hostname,
            local_ip=self.local_ip,
            local_mac=self.local_mac,
            organization_id=self.organization_id,
            api_client=self.api_client,
            heartbeat_url=self.heartbeat_url,
            agent_version=self.agent_version,
            retry_seconds=max(int(os.getenv("NETVISOR_AGENT_ENROLLMENT_RETRY_SECONDS", "15")), 1)
        )
        
        self.telemetry_manager = TelemetryManager(
            api_client=self.api_client,
            telemetry_url=self.telemetry_url
        )
        
        self.config_manager = ConfigManager(
            api_client=self.api_client,
            config_url=self.config_url,
            on_config_changed=self._on_remote_config_changed
        )

        buffer_max_mb = int(os.getenv("NETVISOR_BUFFER_MAX_MB", "50"))
        self.upload_manager = UploadManager(
            api_client=self.api_client,
            upload_url=self.flow_url,
            buffer_db_path=AGENT_RUNTIME_DIR / "buffer.db",
            buffer_max_mb=buffer_max_mb,
            max_batch_size=20,
            max_wait_seconds=5,
            max_memory=10000
        )

        self.heartbeat_manager = HeartbeatManager(
            agent_id=self.agent_id,
            hostname=self.hostname,
            local_ip=self.local_ip,
            local_mac=self.local_mac,
            organization_id=self.organization_id,
            api_client=self.api_client,
            heartbeat_url=self.heartbeat_url,
            enrollment_manager=self.enrollment_manager,
            device_inventory_size_func=lambda: len(self.device_inventory.devices),
            web_inspection_func=lambda: self.web_inspection.status_snapshot() if hasattr(self, 'web_inspection') else {},
            capture_health_func=lambda: self.capture_manager.status_snapshot(),
            upload_health_func=lambda: self.upload_manager.health_snapshot(),
            flow_health_func=self._flow_health_snapshot,
            organization_update_func=self._set_organization_id,
            agent_version=self.agent_version,
            heartbeat_interval=self.heartbeat_interval,
        )

        self.discovery_manager = DiscoveryManager(
            agent_id=self.agent_id,
            organization_id=self.organization_id,
            local_ip=self.local_ip,
            device_detector=self.device_detector,
            device_inventory=self.device_inventory,
            api_client=self.api_client,
            devices_url=self.devices_url,
            discovery_interval=60,
            max_workers=5
        )

        self.capture_manager = CaptureManager(
            agent_id=self.agent_id,
            organization_id=self.organization_id,
            flow_manager=self.flow_manager,
            domain_cache=self.domain_cache,
            interface=self.capture_interface,
            backend_name=self.capture_backend_name,
            verbose=self.verbose
        )

    def _on_remote_config_changed(self, new_config: dict):
        if "telemetry_enabled" in new_config:
            self.telemetry_manager.update_config(
                enabled=new_config.get("telemetry_enabled", True),
                interval=new_config.get("telemetry_interval_seconds", 60)
            )

    def _set_organization_id(self, organization_id: str) -> None:
        if not organization_id or organization_id == self.organization_id:
            return
        self.organization_id = organization_id
        self.enrollment_manager.update_organization_id(organization_id)
        self.flow_manager.organization_id = organization_id
        self.discovery_manager.organization_id = organization_id
        self.capture_manager.organization_id = organization_id
        if hasattr(self, "web_inspection"):
            self.web_inspection.update_context(organization_id=organization_id)

    def _init_agent_id(self):
        AGENT_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        id_file = AGENT_RUNTIME_DIR / "agent_id.txt"
        if id_file.exists():
            with id_file.open("r", encoding="utf-8") as f:
                return f.read().strip()
        new_id = f"AGENT-{uuid.uuid4().hex[:8].upper()}"
        with id_file.open("w", encoding="utf-8") as f:
            f.write(new_id)
        return new_id

    def _load_config(self, path):
        try:
            config_path = Path(path)
            if config_path.exists():
                with config_path.open("r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _resolve_initial_organization_id(self):
        configured = (
            self.config.get("organization_id")
            or os.getenv("NETVISOR_ORGANIZATION_ID")
            or os.getenv("NETVISOR_DEFAULT_ORGANIZATION_ID")
        )
        return configured or "default-org-id"

    def _load_initial_backend_pins(self):
        configured = self.config.get("backend_tls_pins")
        if isinstance(configured, list):
            return configured
        raw = os.getenv("NETVISOR_BACKEND_TLS_PINS_JSON", "").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except ValueError:
            logger.warning("Invalid NETVISOR_BACKEND_TLS_PINS_JSON value; starting without seed pins.")
            return []
        return parsed if isinstance(parsed, list) else []

    def status_snapshot(self):
        web_inspection = self.web_inspection.status_snapshot() if hasattr(self, "web_inspection") else {}
        return {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "version": self.agent_version,
            "organization_id": self.organization_id,
            "local_ip": self.local_ip,
            "local_mac": self.local_mac,
            "background_workers_enabled": self._background_workers_enabled,
            "running": self.is_running,
            "enrollment_status": self.enrollment_manager.enrollment_status,
            "enrollment_pending": self.enrollment_manager.enrollment_pending,
            "enrollment_message": self.enrollment_manager.enrollment_message,
            "upload_queue_depth": self.upload_manager.get_queue_depth(),
            "device_inventory_size": len(self.device_inventory.devices),
            "flow_manager": self.flow_manager.status_snapshot(),
            "network_scope": self.scope_policy.status_snapshot(),
            "capture": self.capture_manager.status_snapshot(),
            "transport": self.api_client.status_snapshot(),
            "web_inspection": web_inspection,
            "config": self.config_manager.get_config(),
            "telemetry_enabled": self.telemetry_manager.enabled,
        }

    def _flow_health_snapshot(self) -> dict:
        snapshot = self.flow_manager.status_snapshot()
        snapshot["network_scope"] = self.scope_policy.status_snapshot()
        return snapshot

    def _start_operational_workers(self) -> None:
        if self._workers_started:
            return

        # Start workers only after enrollment so the backend can return the
        # canonical organization id before discovery/heartbeat traffic begins.
        print("[*] Starting upload worker...")
        threading.Thread(target=self.upload_manager.upload_worker, daemon=True).start()
        print("[*] Starting heartbeat worker...")
        threading.Thread(target=self.heartbeat_manager.heartbeat_worker, daemon=True).start()
        print("[*] Starting discovery engine...")
        threading.Thread(target=self.discovery_manager.discovery_engine, daemon=True).start()
        print("[*] Starting config manager...")
        self.config_manager.start()
        print("[*] Starting telemetry manager...")
        self.telemetry_manager.start()

        if WebInspectionController is not None:
            self.web_inspection = WebInspectionController(
                runtime_dir=AGENT_RUNTIME_DIR / "mitm",
                agent_id=self.agent_id,
                device_ip=self.local_ip,
                organization_id=self.organization_id,
                api_client=self.api_client,
                policy_url=self.web_policy_url,
                upload_url=self.web_events_url,
                proxy_port=self.web_proxy_port,
                policy_refresh_seconds=self.web_policy_refresh_seconds,
            )
            self.web_inspection.start()
            logger.info(
                "Web inspection launchers ready: %s",
                ", ".join(sorted((self.web_inspection.status_snapshot().get("launcher_paths") or {}).values())),
            )
        else:
            logger.warning("Web inspection is disabled because WebInspectionController could not be imported.")

        self._workers_started = True

    def _on_flow_expired(self, summary: FlowSummary):
        """Callback from FlowManager when a flow is ready for upload."""
        try:
            # Add DNS metadata if applicable (simplified for now)
            # In a full impl, we'd correlate DNS queries with flows here
            self.upload_manager.enqueue_record(summary.__dict__)
        except Exception as e:
            logger.warning(f"Failed to enqueue flow summary: {e}")

    def process_packet(self, packet) -> bool:
        """Phase 1: Direct packet to FlowManager for feature extraction."""
        try:
            observation = PacketObservation.from_packet(
                packet,
                source_type="agent",
                metadata_only=False,
                domain_cache=self.domain_cache,
            )
            if observation is None:
                return False

            decision = self.scope_policy.should_accept_observation(observation)
            if not decision.accepted:
                if self.verbose:
                    print(f"{Fore.YELLOW}[DROP]{Style.RESET_ALL} {decision.reason}: {observation.src_ip} -> {observation.dst_ip}")
                return False

            if observation.domain and self.verbose:
                print(f"{Fore.CYAN}[APP]{Style.RESET_ALL} {observation.src_ip} -> {observation.domain}")

            self.flow_manager.update_from_observation(observation)
            return True
        except Exception as e:
            print(f"ERROR in process_packet: {e}")
            logger.error(f"Packet error: {e}")
            return False

    def _detect_local_ip(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect(("10.255.255.255", 1))
                return sock.getsockname()[0]
            finally:
                sock.close()
        except Exception:
            return "127.0.0.1"

    def _detect_local_mac(self):
        try:
            node = uuid.getnode()
            return ":".join(f"{(node >> shift) & 0xff:02x}" for shift in range(40, -1, -8))
        except Exception:
            return "-"

    def stop(self):
        self.is_running = False
        if hasattr(self, "capture_manager"):
            self.capture_manager.stop()
        if hasattr(self, "discovery_manager"):
            self.discovery_manager.stop()
        if hasattr(self, "heartbeat_manager"):
            self.heartbeat_manager.stop()
        if hasattr(self, "upload_manager"):
            self.upload_manager.stop()
        if hasattr(self, "flow_manager"):
            self.flow_manager.stop()
        if hasattr(self, "web_inspection"):
            self.web_inspection.stop()
        if hasattr(self, "config_manager"):
            self.config_manager.stop()
        if hasattr(self, "telemetry_manager"):
            self.telemetry_manager.stop()

    def start(self, timeout=None):
        if self.enrollment_manager.enrollment_pending or not self.api_client.has_credentials():
            organization_id = self.enrollment_manager.await_enrollment()
            if organization_id:
                self._set_organization_id(organization_id)
            if not self.api_client.has_credentials():
                logger.warning("Agent is still pending approval; capture backend will not start yet.")
                return

        if self._background_workers_enabled and not self._workers_started:
            self._start_operational_workers()

        print(f"{Fore.BLUE}[*] Netvisor Hybrid Agent Starting...")
        success, error = self.capture_manager.start(self.process_packet, timeout=timeout)
        if not success and self.capture_manager.capture_backend.backend_name != "scapy":
            logger.warning("Primary capture backend failed: %s. Falling back to Scapy.", error)
            self.capture_manager.stop()
            success, error = self.capture_manager.fallback_to_scapy()
        if not success and error:
            logger.error("Capture backend failed: %s", error)

def main(config_path=DEFAULT_CONFIG_PATH) -> None:
    parser = argparse.ArgumentParser(description="NetVisor Agent")
    parser.add_argument("--health-check", action="store_true", help="Print a startup health snapshot and exit.")
    parser.add_argument("--reset-enrollment", action="store_true", help="Clear stored signed credentials and exit.")
    parser.add_argument("--preflight", action="store_true", help="Run preflight checks, print report, and exit.")
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Packet sniff timeout in seconds. Omit to run continuously until interrupted.",
    )
    args = parser.parse_args()

    # --preflight: run checks, print colored table, exit
    if args.preflight:
        config = NetworkAgent._load_config(None, config_path)
        server_url = config.get("server_url", "http://127.0.0.1:8000")
        interface = (
            os.getenv("NETVISOR_AGENT_CAPTURE_INTERFACE")
            or os.getenv("NETVISOR_CAPTURE_INTERFACE")
            or ""
        ).strip() or None
        results = run_preflight(
            role="agent",
            config=config,
            config_path=config_path,
            server_url=server_url,
            interface=interface,
        )
        all_ok = print_preflight_report(results, role="agent")
        sys.exit(0 if all_ok else 1)

    if args.health_check or args.reset_enrollment:
        agent = NetworkAgent(config_path, start_background_workers=False)
        if args.reset_enrollment:
            agent.api_client.reset_enrollment()
        snapshot = agent.status_snapshot()
        snapshot["ready"] = bool(agent.api_client.status_snapshot().get("has_credentials"))
        snapshot["enrollment_required"] = not snapshot["ready"]
        print(json.dumps(snapshot, indent=2, sort_keys=True))
        sys.exit(0)

    # Normal startup: run preflight as non-blocking diagnostics
    try:
        config = NetworkAgent._load_config(None, config_path)
        server_url = config.get("server_url", "http://127.0.0.1:8000")
        interface = (
            os.getenv("NETVISOR_AGENT_CAPTURE_INTERFACE")
            or os.getenv("NETVISOR_CAPTURE_INTERFACE")
            or ""
        ).strip() or None
        results = run_preflight(
            role="agent",
            config=config,
            config_path=config_path,
            server_url=server_url,
            interface=interface,
        )
        print_preflight_report(results, role="agent")
        # Only block startup for critical capture/permission failures
        critical_failures = [r for r in results if not r.passed and r.severity == "critical"]
        if critical_failures:
            logger.error("Critical preflight failures detected — agent may not capture traffic.")
    except Exception as exc:
        logger.warning("Preflight checks failed to run: %s", exc)

    agent = NetworkAgent(config_path)
    try:
        agent.start(timeout=args.timeout)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Shutting down Netvisor Agent...{Style.RESET_ALL}")
    finally:
        agent.stop()


if __name__ == "__main__":
    main()
