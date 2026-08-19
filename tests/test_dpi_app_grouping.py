from __future__ import annotations

from types import SimpleNamespace

import backend.api.dpi as dpi


class DummyConn:
    def close(self):
        pass


def test_group_app_events_collapses_related_hits():
    events = [
        {
            "device_ip": "10.0.0.2",
            "browser_name": "Chrome",
            "process_name": "chrome.exe",
            "base_domain": "google.com",
            "page_url": "https://www.google.com/search?q=netvisor",
            "page_title": "netvisor - Google Search",
            "content_category": "search",
            "search_query": "netvisor",
            "confidence_score": 0.7,
            "last_seen": "2026-05-20 10:00:00",
        },
        {
            "device_ip": "10.0.0.2",
            "browser_name": "Chrome",
            "process_name": "chrome.exe",
            "base_domain": "google.com",
            "page_url": "https://www.google.com/search?q=netvisor",
            "page_title": "netvisor - Google Search",
            "content_category": "search",
            "search_query": "netvisor",
            "confidence_score": 0.8,
            "last_seen": "2026-05-20 10:00:05",
        },
    ]

    grouped = dpi._group_app_events(events)

    assert len(grouped) == 1
    row = grouped[0]
    assert row["event_count"] == 2
    assert row["search_queries"] == ["netvisor"]
    assert row["page_titles"] == ["netvisor - Google Search"]
    assert row["page_urls"] == ["https://www.google.com/search?q=netvisor"]
    assert row["confidence_score"] == 0.8
    assert row["last_seen"] == "2026-05-20 10:00:05"


def test_dpi_app_route_returns_grouped_activity(monkeypatch):
    fake_events = [
        {
            "device_ip": "10.0.0.2",
            "browser_name": "Chrome",
            "process_name": "chrome.exe",
            "base_domain": "chatgpt.com",
            "page_url": "https://chatgpt.com/",
            "page_title": "ChatGPT",
            "content_category": "ai",
            "search_query": None,
            "confidence_score": 0.95,
            "last_seen": "2026-05-20 10:05:00",
        }
    ]

    monkeypatch.setattr(dpi.web_inspection_service, "get_global_activity", lambda *args, **kwargs: fake_events)
    monkeypatch.setattr(dpi.application_service, "classify_by_domain", lambda domain: "ChatGPT" if "chatgpt.com" in domain else "")
    monkeypatch.setattr(dpi, "get_service_info", lambda domain: ("ChatGPT", "ai"))

    async def run():
        response = await dpi.get_dpi_events_by_app("ChatGPT", limit=100)
        assert response["activity"][0]["event_count"] == 1
        assert response["activity"][0]["group_key"].startswith("chrome|chatgpt.com")

    import asyncio
    asyncio.run(run())
