import pytest
from unittest.mock import MagicMock
from backend.services.web_inspection_service import WebInspectionService
from backend.services.device_service import DeviceService

def test_url_sanitizer_strips_query_parameters_and_tokens():
    service = WebInspectionService()
    
    # 1. URL with sensitive token & session params
    raw_url = "https://auth.example.com/reset-password?token=secret12345&user_id=admin#heading"
    sanitized = service._sanitize_url(raw_url)
    assert sanitized == "https://auth.example.com/reset-password"
    assert "secret12345" not in sanitized
    assert "token" not in sanitized

    # 2. URL with standard search queries
    raw_search = "https://www.google.com/search?q=sensitive+confidential+project&oq=foo"
    sanitized_search = service._sanitize_url(raw_search)
    assert sanitized_search == "https://www.google.com/search"

    # 3. Path without query params remains intact
    plain_url = "https://api.github.com/repos/owner/repo"
    assert service._sanitize_url(plain_url) == plain_url

def test_rolling_device_risk_calculation_with_decay():
    service = DeviceService()
    mock_conn = MagicMock()
    mock_cursor = MagicMock()

    # Simulate 2 risk events:
    # 1. Very recent event (elapsed_seconds = 60, score = 40, weight ~ 1.0)
    # 2. 12 hours old event (elapsed_seconds = 43200, score = 40, weight ~ 0.367)
    mock_cursor.fetchall.return_value = [
        {
            "id": 1,
            "risk_type": "PORT_SCAN",
            "confidence": 1.0,
            "score": 40,
            "timestamp": "2026-08-23 12:00:00",
            "elapsed_seconds": 60,
        },
        {
            "id": 2,
            "risk_type": "VPN_DETECTED",
            "confidence": 1.0,
            "score": 40,
            "timestamp": "2026-08-23 00:00:00",
            "elapsed_seconds": 43200,
        }
    ]
    mock_conn.cursor.return_value = mock_cursor

    res = service.calculate_rolling_device_risk(mock_conn, "192.168.1.50", "default-org")
    assert res["current_score"] > 40.0
    assert res["risk_level"] in ("HIGH", "MEDIUM")
    assert "PORT_SCAN" in res["reasons"]
    assert "VPN_DETECTED" in res["reasons"]
    assert mock_conn.commit.called
