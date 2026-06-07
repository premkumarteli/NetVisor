from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

from agent.security.transport import AgentApiClient
import app.services.release_service as release_module
from app.services.system_service import SystemService
from agent.main import NetworkAgent
from gateway.main import GatewayCollector
from gateway.security.transport import GatewayApiClient
from shared.collector.flow_manager import FlowManager


class _IdentityProtector:
    def protect(self, data: bytes, *, description: str = "") -> bytes:
        return data

    def unprotect(self, data: bytes) -> bytes:
        return data


def test_release_snapshot_reports_metadata(monkeypatch):
    monkeypatch.setattr(release_module.settings, "RELEASE_VERSION", "2026.04.19")
    monkeypatch.setattr(release_module.settings, "RELEASE_CHANNEL", "prod")
    monkeypatch.setattr(release_module.settings, "GIT_COMMIT", "abc123")
    monkeypatch.setattr(release_module.settings, "BUILD_TIMESTAMP", "2026-04-19T10:30:00Z")

    snapshot = release_module.release_service.snapshot()

    assert snapshot["release_version"] == "2026.04.19"
    assert snapshot["release_channel"] == "prod"
    assert snapshot["git_commit"] == "abc123"
    assert snapshot["build_timestamp"] == "2026-04-19T10:30:00Z"
    assert snapshot["uptime_seconds"] >= 0


def test_latest_backup_status_verifies_manifest_and_summary(tmp_path):
    backup_root = Path(tmp_path)
    backup_dir = backup_root / "20260419_120000_test"
    backup_dir.mkdir(parents=True, exist_ok=True)
    (backup_dir / "summary.csv").write_text("table_name,row_count\nflow_logs,2\nalerts,1\n", encoding="utf-8")
    (backup_dir / "manifest.json").write_text(
        json.dumps({"reason": "test", "created_at": "2026-04-19T12:00:00Z", "table_counts": {"flow_logs": 2, "alerts": 1}, "row_count": 3}),
        encoding="utf-8",
    )

    service = SystemService(backup_root=backup_root)
    status = service.latest_backup_status()

    assert status["configured"] is True
    assert status["verified"] is True
    assert status["row_count"] == 3
    assert status["tables"] == {"flow_logs": 2, "alerts": 1}


def test_agent_transport_status_snapshot_reports_state(tmp_path):
    client = AgentApiClient(
        state_path=tmp_path / "agent-state.json",
        bootstrap_api_key="bootstrap-key",
        protector=_IdentityProtector(),
        initial_pins=[{"pin_type": "spki_sha256", "pin_sha256": "A" * 64, "status": "active"}],
    )
    snapshot = client.status_snapshot()

    assert snapshot["bootstrap_api_key_configured"] is True
    assert snapshot["has_credentials"] is False
    assert snapshot["backend_tls_pin_count"] == 1

    client._state["agent_credentials"] = {"agent_id": "AGENT-1", "key_version": 1, "secret": "secret"}
    client._persist()
    snapshot = client.status_snapshot()
    assert snapshot["has_credentials"] is True
    assert snapshot["credential_agent_id"] == "AGENT-1"
    assert snapshot["credential_key_version"] == 1
    assert snapshot["hardening"]["ready"] is True
    assert snapshot["hardening"]["finding_count"] == 0


def test_agent_transport_reset_enrollment_clears_credentials_but_keeps_pins(tmp_path):
    client = AgentApiClient(
        state_path=tmp_path / "agent-state.json",
        bootstrap_api_key="bootstrap-key",
        protector=_IdentityProtector(),
        initial_pins=[{"pin_type": "spki_sha256", "pin_sha256": "A" * 64, "status": "active"}],
    )
    client._state["agent_credentials"] = {"agent_id": "AGENT-1", "key_version": 1, "secret": "secret"}
    client._persist()

    client.reset_enrollment()

    snapshot = client.status_snapshot()
    assert snapshot["has_credentials"] is False
    assert snapshot["backend_tls_pin_count"] == 1


def test_gateway_transport_status_snapshot_reports_state(tmp_path):
    client = GatewayApiClient(
        state_path=tmp_path / "gateway-state.json",
        bootstrap_api_key="bootstrap-key",
        initial_pins=[{"pin_type": "spki_sha256", "pin_sha256": "B" * 64, "status": "active"}],
    )
    snapshot = client.status_snapshot()

    assert snapshot["bootstrap_api_key_configured"] is True
    assert snapshot["has_credentials"] is False
    assert snapshot["backend_tls_pin_count"] == 1

    client._state["gateway_credentials"] = {"gateway_id": "GATEWAY-1", "key_version": 2, "secret": "secret"}
    client._persist()
    snapshot = client.status_snapshot()
    assert snapshot["has_credentials"] is True
    assert snapshot["credential_gateway_id"] == "GATEWAY-1"
    assert snapshot["credential_key_version"] == 2
    assert snapshot["hardening"]["ready"] is True
    assert snapshot["hardening"]["finding_count"] == 0


def test_gateway_transport_reset_enrollment_clears_credentials_but_keeps_pins(tmp_path):
    client = GatewayApiClient(
        state_path=tmp_path / "gateway-state.json",
        bootstrap_api_key="bootstrap-key",
        initial_pins=[{"pin_type": "spki_sha256", "pin_sha256": "B" * 64, "status": "active"}],
    )
    client._state["gateway_credentials"] = {"gateway_id": "GATEWAY-1", "key_version": 2, "secret": "secret"}
    client._persist()

    client.reset_enrollment()

    snapshot = client.status_snapshot()
    assert snapshot["has_credentials"] is False
    assert snapshot["backend_tls_pin_count"] == 1


def test_agent_transport_reset_enrollment_can_drop_pins(tmp_path):
    client = AgentApiClient(
        state_path=tmp_path / "agent-state.json",
        bootstrap_api_key="bootstrap-key",
        protector=_IdentityProtector(),
        initial_pins=[{"pin_type": "spki_sha256", "pin_sha256": "A" * 64, "status": "active"}],
    )
    client._state["agent_credentials"] = {"agent_id": "AGENT-1", "key_version": 1, "secret": "secret"}
    client._persist()

    client.reset_enrollment(preserve_pins=False)

    snapshot = client.status_snapshot()
    assert snapshot["has_credentials"] is False
    assert snapshot["backend_tls_pin_count"] == 0


def test_agent_hardening_guard_blocks_unenrolled_runtime(tmp_path):
    agent = NetworkAgent.__new__(NetworkAgent)
    agent.agent_id = "AGENT-1"
    agent.hostname = "NODE-1"
    agent.agent_version = "v3.0-hybrid"
    agent.organization_id = "ORG-1"
    agent.local_ip = "10.0.0.5"
    agent.local_mac = "00:11:22:33:44:55"
    agent._background_workers_enabled = True
    agent.is_running = True
    agent._enrollment_status = "unknown"
    agent._enrollment_pending = False
    agent._enrollment_message = None
    agent.upload_q = SimpleNamespace(qsize=lambda: 0)
    agent.device_inventory = SimpleNamespace(devices={})
    agent.flow_manager = SimpleNamespace(status_snapshot=lambda: {})
    agent.capture_backend = SimpleNamespace(status_snapshot=lambda: {})
    agent.local_network = "10.0.0.0/24"
    agent.api_key = "bootstrap-key"
    agent.api_client = AgentApiClient(
        state_path=tmp_path / "agent-state.json",
        bootstrap_api_key="bootstrap-key",
        protector=_IdentityProtector(),
        initial_pins=[{"pin_type": "spki_sha256", "pin_sha256": "A" * 64, "status": "active"}],
    )

    try:
        agent._assert_hardening_ready()
        assert False, "Expected unsafe agent runtime to be rejected"
    except RuntimeError as exc:
        assert "unenrolled_agent" in str(exc)


def test_gateway_transport_reset_enrollment_can_drop_pins(tmp_path):
    client = GatewayApiClient(
        state_path=tmp_path / "gateway-state.json",
        bootstrap_api_key="bootstrap-key",
        initial_pins=[{"pin_type": "spki_sha256", "pin_sha256": "B" * 64, "status": "active"}],
    )
    client._state["gateway_credentials"] = {"gateway_id": "GATEWAY-1", "key_version": 2, "secret": "secret"}
    client._persist()

    client.reset_enrollment(preserve_pins=False)

    snapshot = client.status_snapshot()
    assert snapshot["has_credentials"] is False
    assert snapshot["backend_tls_pin_count"] == 0


def test_gateway_hardening_guard_blocks_unenrolled_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_API_KEY", "bootstrap-key")
    monkeypatch.setenv(
        "NETVISOR_BACKEND_TLS_PINS_JSON",
        '[{"pin_type":"spki_sha256","pin_sha256":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","status":"active"}]',
    )
    collector = GatewayCollector(start_background_workers=False)
    collector._background_workers_enabled = True
    collector.capture_interface = "test-interface"
    collector.client._state["gateway_credentials"] = None

    try:
        collector._assert_hardening_ready()
        assert False, "Expected unsafe gateway runtime to be rejected"
    except RuntimeError as exc:
        assert "unenrolled_gateway" in str(exc)


def test_gateway_hardening_guard_blocks_missing_capture_interface(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_API_KEY", "bootstrap-key")
    monkeypatch.setenv(
        "NETVISOR_BACKEND_TLS_PINS_JSON",
        '[{"pin_type":"spki_sha256","pin_sha256":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","status":"active"}]',
    )
    collector = GatewayCollector(start_background_workers=False)
    collector._background_workers_enabled = True
    collector.capture_interface = None
    collector.capture_interface_source = "test"
    collector.client._state["gateway_credentials"] = {"gateway_id": "GATEWAY-1", "key_version": 1, "secret": "secret"}
    collector.client._persist()

    try:
        collector._assert_hardening_ready()
        assert False, "Expected missing capture interface to be rejected"
    except RuntimeError as exc:
        assert "capture_interface_unset" in str(exc)


def test_flow_manager_status_snapshot_reports_counts():
    manager = FlowManager(
        agent_id="AGENT-1",
        organization_id="ORG-1",
        on_flow_expired=lambda summary: None,
        start_worker=False,
    )

    snapshot = manager.status_snapshot()

    assert snapshot["active_flow_count"] == 0
    assert snapshot["max_flows"] >= 1
    assert snapshot["packet_count"] == 0


def _load_bundle_builder():
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "build_deploy_bundles.py"
    spec = importlib.util.spec_from_file_location("build_deploy_bundles_test", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load bundle builder from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_deploy_bundle_includes_systemd_units(tmp_path, monkeypatch):
    builder = _load_bundle_builder()
    monkeypatch.setattr(builder, "ensure_server_frontend_dist", lambda: None)
    bundles = dict(builder.BUNDLES)
    bundles["server"] = [
        item for item in builder.BUNDLES["server"]
        if item[0] != "frontend/dist"
    ]
    monkeypatch.setattr(builder, "BUNDLES", bundles)
    output_root = tmp_path / "deploy"

    agent_bundle = builder.build_bundle("agent", output_root)
    gateway_bundle = builder.build_bundle("gateway", output_root)
    server_bundle = builder.build_bundle("server", output_root)

    assert (agent_bundle / "systemd/netvisor-agent.service").is_file()
    assert (gateway_bundle / "systemd/netvisor-gateway.service").is_file()
    assert (server_bundle / "run_backup_retention.py").is_file()
    assert (server_bundle / "scripts/run_backup_retention.py").is_file()
    assert (server_bundle / "systemd/netvisor-backup-retention.service").is_file()
    assert (server_bundle / "systemd/netvisor-backup-retention.timer").is_file()
