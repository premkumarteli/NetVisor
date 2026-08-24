import os
import platform
from unittest.mock import MagicMock, patch
import pytest

from agent.dpi.quic_guard import QuicGuard, RULE_PREFIX
from agent.dpi.policy import InspectionPolicy


class TestQuicGuard:
    def test_init_properties(self):
        guard = QuicGuard()
        assert guard.rule_name == RULE_PREFIX
        assert guard.is_supported() == (platform.system().lower() == "windows")
        status = guard.status()
        assert "quic_block_supported" in status
        assert "quic_block_is_admin" in status
        assert status["quic_block_active"] is False
        assert status["quic_block_applied_rules"] == []

    def test_apply_block_fails_loudly_when_not_admin(self):
        guard = QuicGuard()
        with patch.object(guard, "is_supported", return_value=True), \
             patch.object(guard, "is_admin", return_value=False):
            success, err = guard.apply_block()
            assert success is False
            assert "Administrator privileges required" in str(err)
            assert guard.status()["quic_block_active"] is False
            assert guard.status()["quic_block_last_error"] is not None

    def test_apply_block_global_rule_success(self):
        guard = QuicGuard()
        with patch.object(guard, "is_supported", return_value=True), \
             patch.object(guard, "is_admin", return_value=True), \
             patch.object(guard, "_run_netsh", return_value=(True, "Ok.")) as mock_netsh:
            success, err = guard.apply_block()
            assert success is True
            assert err is None
            assert guard.status()["quic_block_active"] is True
            assert guard.status()["quic_block_applied_rules"] == [RULE_PREFIX]

            # Verify netsh arguments
            calls = mock_netsh.call_args_list
            # First call is remove_block delete, second is add rule
            add_call = calls[-1][0][0]
            assert "add" in add_call
            assert f"name={RULE_PREFIX}" in add_call
            assert "protocol=UDP" in add_call
            assert "remoteport=443" in add_call
            assert "action=block" in add_call

    def test_apply_block_per_process_rules(self, tmp_path):
        dummy_chrome = tmp_path / "chrome.exe"
        dummy_chrome.write_text("fake binary", encoding="utf-8")
        dummy_edge = tmp_path / "msedge.exe"
        dummy_edge.write_text("fake binary", encoding="utf-8")

        guard = QuicGuard()
        with patch.object(guard, "is_supported", return_value=True), \
             patch.object(guard, "is_admin", return_value=True), \
             patch.object(guard, "_run_netsh", return_value=(True, "Ok.")) as mock_netsh:
            success, err = guard.apply_block(processes=[str(dummy_chrome), str(dummy_edge)])
            assert success is True
            assert err is None
            assert guard.status()["quic_block_active"] is True
            applied = guard.status()["quic_block_applied_rules"]
            assert f"{RULE_PREFIX}_chrome" in applied
            assert f"{RULE_PREFIX}_msedge" in applied

    def test_remove_block_cleans_up_rules(self):
        guard = QuicGuard()
        guard._applied_rules = [f"{RULE_PREFIX}_chrome", f"{RULE_PREFIX}_msedge"]
        guard._active = True

        with patch.object(guard, "is_supported", return_value=True), \
             patch.object(guard, "is_admin", return_value=True), \
             patch.object(guard, "_run_netsh", return_value=(True, "Deleted")) as mock_netsh:
            success, err = guard.remove_block()
            assert success is True
            assert err is None
            assert guard.status()["quic_block_active"] is False
            assert guard.status()["quic_block_applied_rules"] == []
            assert mock_netsh.call_count == 2

    def test_cleanup_orphaned_rules(self):
        guard = QuicGuard()
        with patch.object(guard, "is_supported", return_value=True), \
             patch.object(guard, "is_admin", return_value=True), \
             patch.object(guard, "_run_netsh", return_value=(True, "Deleted")) as mock_netsh:
            guard.cleanup_orphaned_rules()
            assert mock_netsh.call_count == 5
            call_args = mock_netsh.call_args_list[0][0][0]
            assert "delete" in call_args
            assert f"name={RULE_PREFIX}" in call_args


class TestInspectionPolicyQuicToggle:
    def test_policy_defaults_quic_block_to_false(self):
        policy = InspectionPolicy.from_payload({}, agent_id="test-agent", device_ip="192.168.1.50")
        assert policy.enable_quic_block is False
        assert policy.to_payload()["enable_quic_block"] is False

    def test_policy_parses_quic_block_from_payload(self):
        policy = InspectionPolicy.from_payload(
            {"enable_quic_block": True, "inspection_enabled": True},
            agent_id="test-agent",
            device_ip="192.168.1.50"
        )
        assert policy.enable_quic_block is True
        assert policy.to_payload()["enable_quic_block"] is True

    def test_policy_env_var_override(self, monkeypatch):
        monkeypatch.setenv("NETVISOR_DPI_ENABLE_QUIC_BLOCK", "true")
        policy = InspectionPolicy.from_payload({}, agent_id="test-agent", device_ip="192.168.1.50")
        assert policy.enable_quic_block is True
