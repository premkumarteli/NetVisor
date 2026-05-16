"""Tests for shared.collector.preflight module."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from shared.collector.preflight import (
    PreflightResult,
    run_preflight,
    print_preflight_report,
    CRITICAL,
    WARNING,
    INFO,
    _check_config_valid,
    _check_server_reachable,
    _check_interface_available,
    _check_capture_permissions,
    _check_dns_resolution,
    _check_network_scope,
)


class TestPreflightResult:
    def test_str_pass(self):
        result = PreflightResult(check_name="test", passed=True, message="ok")
        assert "[PASS]" in str(result)

    def test_str_fail(self):
        result = PreflightResult(check_name="test", passed=False, message="bad")
        assert "[FAIL]" in str(result)

    def test_default_severity(self):
        result = PreflightResult(check_name="test", passed=True, message="ok")
        assert result.severity == INFO


class TestCheckConfigValid:
    def test_valid_config_with_server_url(self):
        result = _check_config_valid({"server_url": "http://localhost:8000"})
        assert result.passed is True
        assert result.check_name == "config_valid"

    def test_missing_server_url(self):
        result = _check_config_valid({})
        assert result.passed is False
        assert result.severity == WARNING

    def test_config_file_not_found(self, tmp_path):
        missing = tmp_path / "does_not_exist.json"
        result = _check_config_valid({}, config_path=missing)
        assert result.passed is False
        assert result.check_name == "config_file"


class TestCheckServerReachable:
    def test_no_server_url(self):
        result = _check_server_reachable("")
        assert result.passed is False
        assert result.severity == WARNING

    @patch("shared.collector.preflight.requests")
    def test_server_reachable(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests.get.return_value = mock_response
        result = _check_server_reachable("http://localhost:8000")
        assert result.passed is True

    @patch("shared.collector.preflight.requests")
    def test_server_unreachable(self, mock_requests):
        mock_requests.get.side_effect = ConnectionError("refused")
        result = _check_server_reachable("http://localhost:8000")
        assert result.passed is False
        assert result.severity == WARNING  # Not critical


class TestCheckInterfaceAvailable:
    def test_no_interface_configured(self):
        result = _check_interface_available(None)
        assert result.passed is True

    @patch("shared.collector.preflight.psutil")
    def test_interface_exists(self, mock_psutil):
        mock_psutil.net_if_addrs.return_value = {"eth0": [], "lo": []}
        result = _check_interface_available("eth0")
        assert result.passed is True

    @patch("shared.collector.preflight.psutil")
    def test_interface_missing(self, mock_psutil):
        mock_psutil.net_if_addrs.return_value = {"eth0": [], "lo": []}
        result = _check_interface_available("wlan99")
        assert result.passed is False
        assert result.severity == CRITICAL


class TestCheckDnsResolution:
    def test_no_server_url(self):
        result = _check_dns_resolution("")
        assert result.passed is True

    @patch("shared.collector.preflight.socket.gethostbyname")
    def test_dns_resolves(self, mock_dns):
        mock_dns.return_value = "127.0.0.1"
        result = _check_dns_resolution("http://localhost:8000")
        assert result.passed is True


class TestCheckNetworkScope:
    def test_valid_network_scope(self):
        result = _check_network_scope("agent", {"network_scope": "192.168.1.0/24"})
        assert result.passed is True
        assert result.check_name == "network_scope"

    def test_invalid_network_scope_warns(self):
        result = _check_network_scope("gateway", {"network_scope": "not-a-cidr"})
        assert result.passed is False
        assert result.severity == WARNING


class TestRunPreflight:
    def test_returns_list_of_results(self):
        results = run_preflight(role="agent", config={"server_url": "http://localhost:8000"})
        assert isinstance(results, list)
        assert len(results) >= 4  # config, dns, server, interface, permissions
        assert all(isinstance(r, PreflightResult) for r in results)


class TestPrintPreflightReport:
    def test_returns_true_when_no_critical_failures(self, capsys):
        results = [
            PreflightResult(check_name="a", passed=True, message="ok"),
            PreflightResult(check_name="b", passed=False, message="warn", severity=WARNING),
        ]
        assert print_preflight_report(results, role="agent") is True

    def test_returns_false_when_critical_failure(self, capsys):
        results = [
            PreflightResult(check_name="a", passed=False, message="fail", severity=CRITICAL),
        ]
        assert print_preflight_report(results, role="agent") is False
