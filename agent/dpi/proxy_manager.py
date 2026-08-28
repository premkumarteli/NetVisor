from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .mitm_addon import EVENT_PREFIX
from .cert_manager import CertificateManager

logger = logging.getLogger(__name__)


class ProxyManager:
    def __init__(
        self,
        *,
        runtime_dir: Path,
        cert_manager: CertificateManager,
        addon_path: Path,
        port: int,
        on_event: Callable[[dict], None],
        mode: str = "regular",
    ) -> None:
        self.runtime_dir = Path(runtime_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.cert_manager = cert_manager
        self.addon_path = Path(addon_path)
        self.port = int(port)
        self.on_event = on_event
        self.process: Optional[subprocess.Popen] = None
        self.last_error: Optional[str] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._stdout_thread: Optional[threading.Thread] = None
        self._metrics_lock = threading.Lock()
        self._started_at: Optional[str] = None
        self._last_event_at: Optional[str] = None
        self._last_stderr_at: Optional[str] = None
        self._captured_event_count = 0

        self.mode = os.getenv("NETVISOR_DPI_CAPTURE_MODE", mode)
        timeout_env = os.getenv("NETVISOR_DPI_STARTUP_TIMEOUT")
        try:
            self.startup_timeout = float(timeout_env) if timeout_env else 10.0
        except ValueError:
            self.startup_timeout = 10.0

        self.ready_event = threading.Event()
        self._startup_error: Optional[str] = None

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def _mitmdump_path(self) -> Optional[str]:
        discovered = shutil.which("mitmdump")
        if discovered:
            return discovered

        candidate_dirs = [
            Path(sys.executable).resolve().parent,
            Path(sys.executable).resolve().parent / "Scripts",
            Path.home() / "AppData/Roaming/Python/Python313/Scripts",
            Path.home() / "AppData/Roaming/Python/Python312/Scripts",
            Path.home() / "AppData/Roaming/Python/Python311/Scripts",
        ]
        for directory in candidate_dirs:
            candidate = directory / "mitmdump.exe"
            if candidate.exists():
                return str(candidate)
        return None

    def _build_env(self, *, allowed_domains: list[str], snippet_max_bytes: int) -> dict:
        env = os.environ.copy()
        env["NETVISOR_ALLOWED_DOMAINS_JSON"] = json.dumps(allowed_domains)
        env["NETVISOR_SNIPPET_MAX_BYTES"] = str(snippet_max_bytes)
        return env

    def _prepare_mitm_certs(self) -> None:
        self.cert_manager.prepare_runtime_bundle(self.runtime_dir)

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self, *, allowed_domains: list[str], snippet_max_bytes: int) -> tuple[bool, Optional[str]]:
        if self.is_running():
            return True, None

        mitmdump = self._mitmdump_path()
        if not mitmdump:
            self.last_error = "mitmdump not found on PATH"
            return False, self.last_error

        self.cert_manager.cleanup_runtime_bundle(self.runtime_dir)
        try:
            self._prepare_mitm_certs()
        except Exception as exc:
            self.last_error = f"Failed to prepare MITM certificate bundle: {exc}"
            return False, self.last_error

        if self.mode == "local":
            cmd = [
                mitmdump,
                "--set", f"confdir={self.runtime_dir}",
                "--mode", "local",
                "-q",
                "-s", str(self.addon_path),
            ]
        elif self.mode == "local_browsers":
            cmd = [
                mitmdump,
                "--set", f"confdir={self.runtime_dir}",
                "--mode", "local:chrome.exe,msedge.exe,firefox.exe",
                "-q",
                "-s", str(self.addon_path),
            ]
        else:
            cmd = [
                mitmdump,
                "--set", f"confdir={self.runtime_dir}",
                "--listen-host", "127.0.0.1",
                "--listen-port", str(self.port),
                "-q",
                "-s", str(self.addon_path),
            ]

        self.ready_event.clear()
        self._startup_error = None
        self.last_error = None

        try:
            self.process = subprocess.Popen(
                cmd,
                cwd=str(self.runtime_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=self._build_env(
                    allowed_domains=allowed_domains,
                    snippet_max_bytes=snippet_max_bytes,
                ),
            )
        except OSError as exc:
            self.last_error = str(exc)
            self.process = None
            return False, self.last_error

        with self._metrics_lock:
            self._started_at = self._utc_now()
            self._last_event_at = None
            self._last_stderr_at = None
            self._captured_event_count = 0

        self._stdout_thread = threading.Thread(target=self._stdout_worker, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread = threading.Thread(target=self._stderr_worker, daemon=True)
        self._stderr_thread.start()

        self.ready_event.wait(timeout=self.startup_timeout)

        if self.process.poll() is not None:
            self.last_error = self._startup_error or f"mitmdump exited with code {self.process.returncode}"
            self.stop()
            return False, self.last_error

        if self._startup_error:
            self.last_error = self._startup_error
            self.stop()
            return False, self.last_error

        if self.ready_event.is_set():
            time.sleep(0.5)
            if self.process.poll() is not None:
                self.last_error = "mitmdump crashed shortly after starting"
                self.stop()
                return False, self.last_error
            return True, None

        logger.warning("Startup readiness timeout elapsed; assuming mitmdump is running.")
        return True, None

    def stop(self) -> None:
        if not self.process:
            self.cert_manager.cleanup_runtime_bundle(self.runtime_dir)
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None
        self.cert_manager.cleanup_runtime_bundle(self.runtime_dir)

    def _stdout_worker(self) -> None:
        if not self.process or not self.process.stdout:
            return
        for line in self.process.stdout:
            if not line:
                continue

            line_str = line.strip()
            if any(p in line_str for p in ("Proxy server listening", "Local redirector started", "Windows proxy successfully initialized")):
                self.ready_event.set()

            if line.startswith("__NETVISOR_DPI_STATUS__"):
                payload_str = line[len("__NETVISOR_DPI_STATUS__") :].strip()
                try:
                    status_data = json.loads(payload_str)
                    with self._metrics_lock:
                        self._upstream_tls_status = status_data
                except Exception:
                    pass
                continue

            if line.startswith("__NETVISOR_DPI_ALERT__"):
                payload_str = line[len("__NETVISOR_DPI_ALERT__") :].strip()
                try:
                    alert_data = json.loads(payload_str)
                    logger.warning("[DPI Alert] %s", alert_data.get("message"))
                    self.on_event(alert_data)
                except Exception:
                    pass
                continue

            if not line.startswith(EVENT_PREFIX):
                continue
            payload = line[len(EVENT_PREFIX) :].strip()
            logger.info("Captured raw event from mitmdump")
            try:
                with self._metrics_lock:
                    self._last_event_at = self._utc_now()
                    self._captured_event_count += 1
                self.on_event(json.loads(payload))
            except (TypeError, ValueError):
                logger.debug("Discarded invalid mitmproxy event payload")

    def _stderr_worker(self) -> None:
        if not self.process or not self.process.stderr:
            return
        for line in self.process.stderr:
            message = (line or "").strip()
            if not message:
                continue

            if any(p in message for p in ("Proxy server listening", "Local redirector started", "Windows proxy successfully initialized")):
                self.ready_event.set()

            if any(p in message for p in ("Error logged during startup", "Failed to start", "Address already in use", "Permission denied")):
                self._startup_error = message
                self.ready_event.set()

            self.last_error = message
            with self._metrics_lock:
                self._last_stderr_at = self._utc_now()
            logger.info("mitmdump: %s", message)

    def status(self) -> dict:
        with self._metrics_lock:
            started_at = self._started_at
            last_event_at = self._last_event_at
            last_stderr_at = self._last_stderr_at
            captured_event_count = self._captured_event_count
            upstream_tls = dict(getattr(self, "_upstream_tls_status", {}))
        return {
            "proxy_running": self.is_running(),
            "proxy_port": self.port,
            "proxy_pid": self.process.pid if self.is_running() and self.process else None,
            "proxy_mode": self.mode,
            "started_at": started_at,
            "last_event_at": last_event_at,
            "last_stderr_at": last_stderr_at,
            "captured_event_count": captured_event_count,
            "last_error": self.last_error,
            "upstream_tls_healed_domains": upstream_tls.get("healed_domains", []),
            "upstream_tls_recovering_domains": upstream_tls.get("recovering_domains", []),
            "upstream_tls_persistently_failing_domains": upstream_tls.get("persistently_failing_domains", []),
        }
