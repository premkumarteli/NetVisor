from __future__ import annotations

import json
from pathlib import Path

import shared.collector.preflight as preflight


def test_preflight_flags_localhost_target_as_critical(tmp_path: Path):
    config_path = tmp_path / "agent.json"
    config_path.write_text("{}", encoding="utf-8")

    results = preflight.run_preflight(
        role="agent",
        config_path=config_path,
        server_url="http://127.0.0.1:8000",
        interface=None,
    )

    target = next(result for result in results if result.check_name == "server_target")
    assert not target.passed
    assert target.severity == "critical"
    assert preflight.preflight_exit_code(results) == 1


def test_preflight_accepts_remote_target_when_connectivity_is_mocked(tmp_path: Path, monkeypatch):
    config_path = tmp_path / "gateway.json"
    config_path.write_text("{}", encoding="utf-8")

    class DummyResponse:
        ok = True
        status_code = 200

    monkeypatch.setattr(preflight, "gethostbyname", lambda hostname: "10.0.0.5")
    monkeypatch.setattr(preflight, "requests", type("Req", (), {"get": staticmethod(lambda *args, **kwargs: DummyResponse())})())

    results = preflight.run_preflight(
        role="gateway",
        config_path=config_path,
        server_url="http://10.0.0.5:8000",
        interface=None,
    )

    target = next(result for result in results if result.check_name == "server_target")
    assert target.passed
    assert any(result.check_name == "server_reachable" and result.passed for result in results)
    assert preflight.preflight_exit_code(results) == 0


def test_preflight_report_serializes_to_json(tmp_path: Path):
    config_path = tmp_path / "agent.json"
    config_path.write_text("{}", encoding="utf-8")

    results = preflight.run_preflight(
        role="agent",
        config_path=config_path,
        server_url="http://10.0.0.5:8000",
        interface=None,
    )

    payload = preflight.serialize_preflight_results(results)
    data = json.loads(payload)
    assert isinstance(data, list)
    assert data
    assert {"check_name", "passed", "message", "severity"} <= set(data[0])
