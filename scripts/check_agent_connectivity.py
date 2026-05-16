from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from shared.collector.preflight import run_preflight, print_preflight_report


def _config_path() -> Path:
    return Path(__file__).resolve().parents[1] / "config" / "agent.json"


def _server_base_url(config: dict) -> str:
    configured = str(config.get("server_url") or "").strip().rstrip("/")
    if not configured:
        return ""
    if "/api/v1/collect" in configured:
        return configured.split("/api/v1/collect", 1)[0]
    if configured.endswith("/api/v1"):
        return configured.rsplit("/api/v1", 1)[0]
    return configured


def main() -> int:
    config_path = _config_path()
    config = {}
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as handle:
            config = json.load(handle)

    base_url = _server_base_url(config)
    
    if base_url:
        parsed = urlsplit(base_url)
        print(f"[*] Agent config: {config_path}")
        print(f"[*] Server base:  {base_url}")
        print(f"[*] Target host:  {parsed.hostname}:{parsed.port or 80}\n")
    else:
        print(f"[*] Agent config: {config_path}")
        print("[!] config/agent.json has no server_url. Preflight will likely fail.\n")

    results = run_preflight(
        role="agent",
        config=config,
        server_url=base_url,
        interface=config.get("capture_interface")
    )
    all_ok = print_preflight_report(results, role="agent")
    
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
