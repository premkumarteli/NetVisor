from __future__ import annotations

import argparse
import json
from pathlib import Path

from shared.collector import preflight_exit_code, print_preflight_report, run_preflight, serialize_preflight_results


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AGENT_CONFIG = PROJECT_ROOT / "config" / "agent.json"
DEFAULT_GATEWAY_CONFIG = PROJECT_ROOT / "config" / "gateway.json"


def _load_server_url(config_path: Path) -> str | None:
    if not config_path.exists():
        return None
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        return None
    return str(data.get("server_url") or "").strip() or None


def main() -> int:
    parser = argparse.ArgumentParser(description="Run NetVisor collector preflight checks.")
    parser.add_argument("--role", choices=["agent", "gateway"], default="agent")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--interface", default=None)
    args = parser.parse_args()

    config_path = args.config or (DEFAULT_AGENT_CONFIG if args.role == "agent" else DEFAULT_GATEWAY_CONFIG)
    server_url = _load_server_url(config_path)
    results = run_preflight(role=args.role, config_path=config_path, server_url=server_url, interface=args.interface)
    print_preflight_report(results, title=f"NetVisor {args.role.title()} Preflight")
    print(serialize_preflight_results(results))
    return preflight_exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
