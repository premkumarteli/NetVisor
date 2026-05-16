from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "build" / "deploy"
CANONICAL_RUNTIME_ROOTS = {
    "app",
    "agent",
    "gateway",
    "shared",
    "database",
    "frontend",
    "config",
    "deployment",
    "scripts",
    "run_server.py",
    "run_flow_worker.py",
    "run_backup_retention.py",
    "run_agent.py",
    "run_gateway.py",
    "requirements-server.txt",
    "requirements-agent.txt",
    "requirements-gateway.txt",
}
IGNORE_PATTERNS = shutil.ignore_patterns(
    "__pycache__",
    "*.pyc",
    "*.pyo",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".env",
)


BUNDLES = {
    "server": [
        ("app", "app"),
        ("shared", "shared"),
        ("database/init.sql", "database/init.sql"),
        ("database/migrations", "database/migrations"),
        ("frontend/dist", "frontend/dist"),
        ("requirements-server.txt", "requirements.txt"),
        ("run_server.py", "run_server.py"),
        ("run_flow_worker.py", "run_flow_worker.py"),
        ("run_backup_retention.py", "run_backup_retention.py"),
        ("scripts/run_server.py", "scripts/run_server.py"),
        ("scripts/run_flow_worker.py", "scripts/run_flow_worker.py"),
        ("scripts/run_backup_retention.py", "scripts/run_backup_retention.py"),
        ("deployment/server/README.md", "README.md"),
        ("deployment/server/.env.example", ".env.example"),
        ("deployment/server/docker-compose.yml", "docker-compose.yml"),
        ("deployment/server/Caddyfile", "Caddyfile"),
        ("deployment/server/systemd/netvisor-backup-retention.service", "systemd/netvisor-backup-retention.service"),
        ("deployment/server/systemd/netvisor-backup-retention.timer", "systemd/netvisor-backup-retention.timer"),
    ],
    "agent": [
        ("agent", "agent"),
        ("shared", "shared"),
        ("config/agent.json", "config/agent.json"),
        ("requirements-agent.txt", "requirements.txt"),
        ("run_agent.py", "run_agent.py"),
        ("scripts/run_agent.py", "scripts/run_agent.py"),
        ("scripts/check_agent_connectivity.py", "scripts/check_agent_connectivity.py"),
        ("scripts/launch_personal_chrome_dpi.cmd", "scripts/launch_personal_chrome_dpi.cmd"),
        ("deployment/agent/setup_and_run.bat", "setup_and_run.bat"),
        ("deployment/agent/systemd/netvisor-agent.service", "systemd/netvisor-agent.service"),
        ("deployment/agent/README.md", "README.md"),
        ("deployment/agent/.env.example", ".env.example"),
    ],
    "gateway": [
        ("gateway", "gateway"),
        ("shared", "shared"),
        ("requirements-gateway.txt", "requirements.txt"),
        ("run_gateway.py", "run_gateway.py"),
        ("scripts/run_gateway.py", "scripts/run_gateway.py"),
        ("deployment/gateway/systemd/netvisor-gateway.service", "systemd/netvisor-gateway.service"),
        ("deployment/gateway/README.md", "README.md"),
        ("deployment/gateway/.env.example", ".env.example"),
    ],
}


def validate_bundle_sources() -> None:
    for bundle_name, items in BUNDLES.items():
        for source_rel, _destination_rel in items:
            root = source_rel.split("/", 1)[0]
            if root == "legacy":
                raise ValueError(f"Bundle '{bundle_name}' must not include archived legacy sources: {source_rel}")
            if root not in CANONICAL_RUNTIME_ROOTS:
                raise ValueError(f"Bundle '{bundle_name}' references non-canonical source root: {source_rel}")


def ensure_server_frontend_dist() -> None:
    dist_index = PROJECT_ROOT / "frontend" / "dist" / "index.html"
    if dist_index.exists():
        return

    frontend_root = PROJECT_ROOT / "frontend"
    print("[*] frontend/dist is missing; building the frontend bundle before packaging the server role...")
    try:
        subprocess.run(["npm", "run", "build"], cwd=frontend_root, check=True)
    except FileNotFoundError as exc:
        raise FileNotFoundError("npm is required to build the server bundle frontend asset") from exc

    if not dist_index.exists():
        raise FileNotFoundError("frontend build completed but frontend/dist/index.html is still missing")


def copy_item(source_rel: str, destination_rel: str, bundle_root: Path) -> None:
    source = PROJECT_ROOT / source_rel
    destination = bundle_root / destination_rel

    if not source.exists():
        raise FileNotFoundError(f"Required bundle asset is missing: {source}")

    destination.parent.mkdir(parents=True, exist_ok=True)

    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True, ignore=IGNORE_PATTERNS)
    else:
        shutil.copy2(source, destination)


def _agent_collect_url(server_url: str) -> str:
    normalized = str(server_url or "").strip().rstrip("/")
    if not normalized:
        return ""
    if "/api/v1/collect" in normalized:
        return normalized
    if normalized.endswith("/api/v1"):
        return f"{normalized}/collect/packet"
    return f"{normalized}/api/v1/collect/packet"


def _stamp_agent_server_url(bundle_root: Path, server_url: str | None) -> None:
    collect_url = _agent_collect_url(server_url or "")
    if not collect_url:
        return

    config_path = bundle_root / "config" / "agent.json"
    with config_path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    base_url = collect_url.split("/api/v1/collect", 1)[0]
    config["server_url"] = collect_url
    config["heartbeat_url"] = f"{base_url}/api/v1/collect/heartbeat"

    with config_path.open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")


def _scan_and_remove_env_files(bundle_root: Path) -> None:
    for env_file in bundle_root.rglob(".env"):
        print(f"[!] Security Guard: Found and deleted accidental .env file in bundle: {env_file}")
        try:
            env_file.unlink()
        except OSError:
            pass

def build_bundle(bundle_name: str, output_root: Path, *, agent_server_url: str | None = None) -> Path:
    bundle_root = output_root / bundle_name
    if bundle_root.exists():
        shutil.rmtree(bundle_root)

    bundle_root.mkdir(parents=True, exist_ok=True)
    if bundle_name == "server":
        ensure_server_frontend_dist()

    for source_rel, destination_rel in BUNDLES[bundle_name]:
        copy_item(source_rel, destination_rel, bundle_root)

    if bundle_name == "agent":
        _stamp_agent_server_url(bundle_root, agent_server_url)

    _scan_and_remove_env_files(bundle_root)

    return bundle_root


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build deployable NetVisor runtime bundles.")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output directory for generated bundles (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--role",
        choices=sorted(BUNDLES.keys()),
        action="append",
        dest="roles",
        help="Only build the named role. Repeat to build multiple roles.",
    )
    parser.add_argument(
        "--agent-server-url",
        default=None,
        help="Server base URL to write into agent config, e.g. http://10.159.79.96:8000",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    validate_bundle_sources()
    output_root = args.output.resolve()
    roles = args.roles or sorted(BUNDLES.keys())

    output_root.mkdir(parents=True, exist_ok=True)

    if args.agent_server_url:
        if "localhost" in args.agent_server_url or "127.0.0.1" in args.agent_server_url:
            print(f"[!] WARNING: The provided agent server URL '{args.agent_server_url}' contains localhost/127.0.0.1.")
            print(f"[!] WARNING: Remote agents will fail to connect. Use an IP address or hostname accessible by the agent.")

    print(f"[*] Building NetVisor deploy bundles into: {output_root}")
    for role in roles:
        bundle_root = build_bundle(role, output_root, agent_server_url=args.agent_server_url)
        print(f"[+] Built {role} bundle: {bundle_root}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
