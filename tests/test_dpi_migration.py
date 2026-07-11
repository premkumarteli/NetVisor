from __future__ import annotations

import os
import json
import threading
import time
from pathlib import Path
import pytest

from agent.dpi.proxy_manager import ProxyManager
from agent.dpi.cert_manager import CertificateManager
from agent.dpi.controller import WebInspectionController
from agent.dpi.policy import InspectionPolicy

class FakeProcess:
    def __init__(self, stdout_lines=None, stderr_lines=None, returncode=None, delay=0.0):
        self.stdout = stdout_lines or []
        self.stderr = stderr_lines or []
        self._returncode = returncode
        self.pid = 9999
        self.delay = delay
        self.start_time = time.time()

    def poll(self):
        if self.delay > 0 and time.time() - self.start_time < self.delay:
            return None
        return self._returncode

    @property
    def returncode(self):
        return self.poll()


    def terminate(self):
        self._returncode = -15

    def wait(self, timeout=None):
        return self._returncode

    def kill(self):
        self._returncode = -9


class FakeCertManager:
    def __init__(self, is_installed_val=True):
        self.is_installed_val = is_installed_val
        self.trust_scope = "CurrentUser"

    def cleanup_runtime_bundle(self, target_dir):
        pass

    def prepare_runtime_bundle(self, target_dir):
        pass

    def ensure_ca_files(self):
        pass

    def status(self):
        return {
            "ca_installed": self.is_installed_val,
            "ca_status": "installed" if self.is_installed_val else "missing",
            "trust_scope": self.trust_scope,
        }

    def install_if_needed(self):
        self.is_installed_val = True
        return True, None


class FakeApiClient:
    def request(self, method, url, *, json_body=None, params=None, timeout=10):
        raise AssertionError("Network calls not expected")


def test_proxy_manager_command_construction(monkeypatch, tmp_path):
    # Verify command construction for all three modes
    runtime_dir = Path(tmp_path)
    
    # Mode: regular (default)
    pm_reg = ProxyManager(
        runtime_dir=runtime_dir,
        cert_manager=FakeCertManager(),
        addon_path=runtime_dir / "addon.py",
        port=8899,
        on_event=lambda e: None,
        mode="regular"
    )
    monkeypatch.setattr(pm_reg, "_mitmdump_path", lambda: "mitmdump")
    monkeypatch.setattr(pm_reg, "_prepare_mitm_certs", lambda: None)
    
    cmd_constructed = []
    def fake_popen_reg(cmd, **kwargs):
        cmd_constructed.extend(cmd)
        return FakeProcess()
    monkeypatch.setattr("agent.dpi.proxy_manager.subprocess.Popen", fake_popen_reg)
    pm_reg.start(allowed_domains=["example.com"], snippet_max_bytes=256)
    assert "--mode" not in cmd_constructed
    assert "--listen-port" in cmd_constructed
    assert "8899" in cmd_constructed
    pm_reg.stop()

    # Mode: local
    pm_local = ProxyManager(
        runtime_dir=runtime_dir,
        cert_manager=FakeCertManager(),
        addon_path=runtime_dir / "addon.py",
        port=8899,
        on_event=lambda e: None,
        mode="local"
    )
    monkeypatch.setattr(pm_local, "_mitmdump_path", lambda: "mitmdump")
    monkeypatch.setattr(pm_local, "_prepare_mitm_certs", lambda: None)
    
    cmd_constructed.clear()
    def fake_popen_local(cmd, **kwargs):
        cmd_constructed.extend(cmd)
        return FakeProcess()
    monkeypatch.setattr("agent.dpi.proxy_manager.subprocess.Popen", fake_popen_local)
    pm_local.start(allowed_domains=["example.com"], snippet_max_bytes=256)
    assert "--mode" in cmd_constructed
    assert "local" in cmd_constructed
    pm_local.stop()

    # Mode: local_browsers
    pm_lb = ProxyManager(
        runtime_dir=runtime_dir,
        cert_manager=FakeCertManager(),
        addon_path=runtime_dir / "addon.py",
        port=8899,
        on_event=lambda e: None,
        mode="local_browsers"
    )
    monkeypatch.setattr(pm_lb, "_mitmdump_path", lambda: "mitmdump")
    monkeypatch.setattr(pm_lb, "_prepare_mitm_certs", lambda: None)
    
    cmd_constructed.clear()
    def fake_popen_lb(cmd, **kwargs):
        cmd_constructed.extend(cmd)
        return FakeProcess()
    monkeypatch.setattr("agent.dpi.proxy_manager.subprocess.Popen", fake_popen_lb)
    pm_lb.start(allowed_domains=["example.com"], snippet_max_bytes=256)
    assert "--mode" in cmd_constructed
    assert "local:chrome.exe,msedge.exe,firefox.exe" in cmd_constructed
    pm_lb.stop()


def test_controller_conditional_wrapper_creation(monkeypatch, tmp_path):
    # Mode: regular should call wrapper creation
    controller_reg = WebInspectionController(
        runtime_dir=tmp_path,
        agent_id="AGENT-1",
        device_ip="10.0.0.5",
        organization_id="default-org-id",
        api_client=FakeApiClient(),
        policy_url="http://localhost/policy",
        upload_url="http://localhost/upload",
        proxy_port=8899,
    )
    controller_reg.proxy_manager.mode = "regular"
    controller_reg.current_policy = InspectionPolicy.from_payload(
        {"inspection_enabled": True}, agent_id="AGENT-1", device_ip="10.0.0.5"
    )
    
    wrappers_called = [False]
    def fake_create_wrappers():
        wrappers_called[0] = True
        return {"chrome.exe": "launch_chrome.cmd"}
    
    monkeypatch.setattr(controller_reg.browser_launcher, "create_wrappers", fake_create_wrappers)
    monkeypatch.setattr(controller_reg.cert_manager, "ensure_ca_files", lambda: None)
    monkeypatch.setattr(controller_reg.cert_manager, "status", lambda: {"ca_installed": True})
    monkeypatch.setattr(controller_reg.proxy_manager, "start", lambda **kw: (True, None))
    
    controller_reg._apply_policy()
    assert wrappers_called[0] is True
    assert controller_reg.status_snapshot()["launcher_paths"] == {"chrome.exe": "launch_chrome.cmd"}

    # Mode: local_browsers should skip wrapper creation
    controller_lb = WebInspectionController(
        runtime_dir=tmp_path,
        agent_id="AGENT-1",
        device_ip="10.0.0.5",
        organization_id="default-org-id",
        api_client=FakeApiClient(),
        policy_url="http://localhost/policy",
        upload_url="http://localhost/upload",
        proxy_port=8899,
    )
    controller_lb.proxy_manager.mode = "local_browsers"
    controller_lb.current_policy = InspectionPolicy.from_payload(
        {"inspection_enabled": True}, agent_id="AGENT-1", device_ip="10.0.0.5"
    )
    
    wrappers_called[0] = False
    monkeypatch.setattr(controller_lb.browser_launcher, "create_wrappers", fake_create_wrappers)
    monkeypatch.setattr(controller_lb.cert_manager, "ensure_ca_files", lambda: None)
    monkeypatch.setattr(controller_lb.cert_manager, "status", lambda: {"ca_installed": True})
    # Mock admin privilege
    monkeypatch.setattr("ctypes.windll.shell32.IsUserAnAdmin", lambda: True, raising=False)
    monkeypatch.setattr(controller_lb.proxy_manager, "start", lambda **kw: (True, None))
    
    controller_lb._apply_policy()
    assert wrappers_called[0] is False
    snapshot = controller_lb.status_snapshot()
    assert snapshot["launcher_paths"] == {}
    assert snapshot["browser_launcher_deprecated"] is True


def test_proxy_manager_readiness_success(monkeypatch, tmp_path):
    runtime_dir = Path(tmp_path)
    pm = ProxyManager(
        runtime_dir=runtime_dir,
        cert_manager=FakeCertManager(),
        addon_path=runtime_dir / "addon.py",
        port=8899,
        on_event=lambda e: None,
        mode="local_browsers"
    )
    monkeypatch.setattr(pm, "_mitmdump_path", lambda: "mitmdump")
    monkeypatch.setattr(pm, "_prepare_mitm_certs", lambda: None)
    
    fake_proc = FakeProcess(stdout_lines=["Local redirector started.\n"])
    monkeypatch.setattr("agent.dpi.proxy_manager.subprocess.Popen", lambda *a, **k: fake_proc)
    
    # We need to simulate stdout worker parsing the lines
    def fake_stdout_worker():
        pm.ready_event.set()
        
    monkeypatch.setattr(pm, "_stdout_worker", fake_stdout_worker)
    
    success, error = pm.start(allowed_domains=[], snippet_max_bytes=256)
    assert success is True
    assert error is None
    pm.stop()


def test_proxy_manager_early_process_exit(monkeypatch, tmp_path):
    runtime_dir = Path(tmp_path)
    pm = ProxyManager(
        runtime_dir=runtime_dir,
        cert_manager=FakeCertManager(),
        addon_path=runtime_dir / "addon.py",
        port=8899,
        on_event=lambda e: None,
        mode="local_browsers"
    )
    pm.startup_timeout = 1.0
    monkeypatch.setattr(pm, "_mitmdump_path", lambda: "mitmdump")
    monkeypatch.setattr(pm, "_prepare_mitm_certs", lambda: None)
    
    # Exit code is 1 (immediate crash)
    fake_proc = FakeProcess(returncode=1)
    monkeypatch.setattr("agent.dpi.proxy_manager.subprocess.Popen", lambda *a, **k: fake_proc)
    
    success, error = pm.start(allowed_domains=[], snippet_max_bytes=256)
    assert success is False
    assert "exited with code 1" in error
    pm.stop()


def test_proxy_manager_fatal_startup_log(monkeypatch, tmp_path):
    runtime_dir = Path(tmp_path)
    pm = ProxyManager(
        runtime_dir=runtime_dir,
        cert_manager=FakeCertManager(),
        addon_path=runtime_dir / "addon.py",
        port=8899,
        on_event=lambda e: None,
        mode="local_browsers"
    )
    pm.startup_timeout = 1.0
    monkeypatch.setattr(pm, "_mitmdump_path", lambda: "mitmdump")
    monkeypatch.setattr(pm, "_prepare_mitm_certs", lambda: None)
    
    fake_proc = FakeProcess()
    monkeypatch.setattr("agent.dpi.proxy_manager.subprocess.Popen", lambda *a, **k: fake_proc)
    
    def fake_stderr_worker():
        pm._startup_error = "Failed to start the interception process as administrator."
        pm.ready_event.set()
        
    monkeypatch.setattr(pm, "_stderr_worker", fake_stderr_worker)
    
    success, error = pm.start(allowed_domains=[], snippet_max_bytes=256)
    assert success is False
    assert "Failed to start" in error
    pm.stop()


def test_proxy_manager_startup_timeout(monkeypatch, tmp_path):
    runtime_dir = Path(tmp_path)
    pm = ProxyManager(
        runtime_dir=runtime_dir,
        cert_manager=FakeCertManager(),
        addon_path=runtime_dir / "addon.py",
        port=8899,
        on_event=lambda e: None,
        mode="local_browsers"
    )
    # Set timeout very low
    pm.startup_timeout = 0.1
    monkeypatch.setattr(pm, "_mitmdump_path", lambda: "mitmdump")
    monkeypatch.setattr(pm, "_prepare_mitm_certs", lambda: None)
    
    # Process is still running (returncode is None)
    fake_proc = FakeProcess(delay=10.0)
    monkeypatch.setattr("agent.dpi.proxy_manager.subprocess.Popen", lambda *a, **k: fake_proc)
    
    success, error = pm.start(allowed_domains=[], snippet_max_bytes=256)
    # Since it is still running, it fallbacks to success
    assert success is True
    assert error is None
    pm.stop()


def test_cert_manager_fingerprint_matching(monkeypatch, tmp_path):
    cm = CertificateManager(tmp_path, trust_scope="CurrentUser")
    
    # Mock _find_powershell
    monkeypatch.setattr(cm, "_find_powershell", lambda: "powershell")
    
    # Mock subprocess.run to simulate cert check outputs
    expected_thumbprint = "AAABBB123"
    monkeypatch.setattr(cm, "certificate_thumbprint_sha256", lambda: expected_thumbprint)
    
    called_args = []
    def fake_run(args, **kwargs):
        called_args.append(args)
        # return FOUND
        import subprocess
        return subprocess.CompletedProcess(args, 0, stdout="FOUND", stderr="")
        
    monkeypatch.setattr("agent.dpi.cert_manager.subprocess.run", fake_run)
    
    assert cm.is_installed() is True
    assert len(called_args) == 1
    # Check that powershell command references the expected store scope "CurrentUser"
    assert "CurrentUser" in called_args[0][-1]
    assert "LocalMachine" not in called_args[0][-1]

    # Switch scope to LocalMachine
    cm.trust_scope = "LocalMachine"
    called_args.clear()
    assert cm.is_installed() is True
    assert len(called_args) == 1
    assert "LocalMachine" in called_args[0][-1]
    assert "CurrentUser" not in called_args[0][-1]
