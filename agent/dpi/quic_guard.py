from __future__ import annotations

import atexit
import ctypes
import logging
import os
import platform
import subprocess
import sys
from typing import Optional

logger = logging.getLogger(__name__)

RULE_PREFIX = "NetVisor_Block_QUIC_UDP443"


class QuicGuard:
    """Manages OS-level firewall rules to block outbound UDP 443 (QUIC),
    forcing browsers to downgrade to TCP-based HTTPS (HTTP/2 or HTTP/1.1)
    which can then be intercepted by the DPI proxy.
    """

    def __init__(self, rule_name: str = RULE_PREFIX) -> None:
        self.rule_name = rule_name
        self.is_windows = platform.system().lower() == "windows"
        self._active = False
        self._last_error: Optional[str] = None
        self._applied_rules: list[str] = []

        # Register exit handler to ensure firewall rules are purged on process exit
        atexit.register(self.remove_block)

    def is_admin(self) -> bool:
        """Check if the current process has Administrator privileges."""
        if not self.is_windows:
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)
        except Exception:
            return False

    def is_supported(self) -> bool:
        """Check if QUIC blocking via Windows Firewall is supported in this environment."""
        return self.is_windows

    def _run_netsh(self, args: list[str], timeout: int = 10) -> tuple[bool, str]:
        """Execute a netsh command safely with timeout."""
        cmd = ["netsh", "advfirewall", "firewall"] + args
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
            output = (res.stdout or "") + (res.stderr or "")
            return (res.returncode == 0, output.strip())
        except subprocess.TimeoutExpired:
            return (False, "netsh command timed out")
        except Exception as exc:
            return (False, str(exc))

    def cleanup_orphaned_rules(self) -> None:
        """Delete any stale NetVisor QUIC block rules from previous unclean shutdowns."""
        if not self.is_supported():
            return
        if not self.is_admin():
            logger.debug("[QUIC Guard] Skipping startup orphan cleanup (un-elevated process)")
            return

        candidate_names = [
            self.rule_name,
            f"{self.rule_name}_chrome",
            f"{self.rule_name}_msedge",
            f"{self.rule_name}_firefox",
            f"{self.rule_name}_brave",
        ]
        for name in candidate_names:
            success, output = self._run_netsh(["delete", "rule", f"name={name}"])
            if success:
                logger.info("[QUIC Guard] Cleaned up orphaned firewall rule: %s", name)

    def apply_block(self, processes: Optional[list[str]] = None) -> tuple[bool, Optional[str]]:
        """Add Windows Firewall rule(s) to block outbound UDP 443.
        If `processes` (list of absolute executable paths) are given, creates per-process
        rules. Otherwise creates a single global outbound UDP 443 block.
        """
        if not self.is_supported():
            self._last_error = "QUIC blocking is only supported on Windows."
            logger.warning("[QUIC Guard] %s", self._last_error)
            return False, self._last_error

        if not self.is_admin():
            self._last_error = "Administrator privileges required to configure Windows Firewall."
            logger.warning("[QUIC Guard] %s Degrading QUIC inspection.", self._last_error)
            return False, self._last_error

        # Remove any existing rules first
        self.remove_block()

        rules_to_create = []
        if processes:
            for proc_path in processes:
                if proc_path and os.path.exists(proc_path):
                    rule_suffix = os.path.splitext(os.path.basename(proc_path))[0]
                    name = f"{self.rule_name}_{rule_suffix}"
                    rules_to_create.append((name, proc_path))

        if not rules_to_create:
            rules_to_create.append((self.rule_name, None))

        created = []
        for name, program in rules_to_create:
            args = [
                "add", "rule",
                f"name={name}",
                "dir=out",
                "action=block",
                "protocol=UDP",
                "remoteport=443",
            ]
            if program:
                args.append(f"program={program}")

            success, output = self._run_netsh(args)
            if success:
                logger.info("[QUIC Guard] Added firewall rule '%s' (blocking UDP 443 -> forcing TCP fallback)", name)
                created.append(name)
            else:
                self._last_error = f"Failed to add rule '{name}': {output}"
                logger.warning("[QUIC Guard] %s", self._last_error)
                # Cleanup any partially created rules
                for created_name in created:
                    self._run_netsh(["delete", "rule", f"name={created_name}"])
                self._active = False
                return False, self._last_error

        self._applied_rules = created
        self._active = True
        self._last_error = None
        return True, None

    def remove_block(self) -> tuple[bool, Optional[str]]:
        """Remove all active NetVisor QUIC block firewall rules."""
        if not self.is_supported() or not self.is_admin():
            self._active = False
            return True, None

        rules_to_delete = list(self._applied_rules) if self._applied_rules else [self.rule_name]
        for name in rules_to_delete:
            self._run_netsh(["delete", "rule", f"name={name}"])
            logger.info("[QUIC Guard] Removed firewall rule '%s'", name)

        self._applied_rules = []
        self._active = False
        self._last_error = None
        return True, None

    def status(self) -> dict:
        """Return snapshot of QUIC guard status."""
        return {
            "quic_block_supported": self.is_supported(),
            "quic_block_is_admin": self.is_admin(),
            "quic_block_active": self._active,
            "quic_block_applied_rules": list(self._applied_rules),
            "quic_block_last_error": self._last_error,
        }
