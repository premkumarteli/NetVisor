from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import datetime
import json
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "build" / "deploy"
CANONICAL_RUNTIME_ROOTS = {
    "backend",
    "agent",
    "gateway",
    "shared",
    "infra",
    "frontend",
    "config",
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
    ".env.*",
    "*.session",
    "*.db",
    "node_modules",
)


BUNDLES = {
    "server": [
        ("backend", "backend"),
        ("packet_engine", "packet_engine"),
        ("proto", "proto"),
        ("intel", "intel"),
        ("engine", "engine"),
        ("security", "security"),
        ("collector", "collector"),
        ("infra/database/init.sql", "database/init.sql"),
        ("infra/database/migrations", "database/migrations"),
        ("frontend/dist", "frontend/dist"),
        ("requirements-server.txt", "requirements.txt"),
        ("run_server.py", "run_server.py"),
        ("run_flow_worker.py", "run_flow_worker.py"),
        ("run_backup_retention.py", "run_backup_retention.py"),
        ("scripts/run_server.py", "scripts/run_server.py"),
        ("scripts/run_flow_worker.py", "scripts/run_flow_worker.py"),
        ("scripts/run_backup_retention.py", "scripts/run_backup_retention.py"),
        ("infra/deployment/server/README.md", "README.md"),
        ("infra/deployment/server/.env.example", ".env.example"),
        ("infra/deployment/server/docker-compose.yml", "docker-compose.yml"),
        ("infra/deployment/server/Caddyfile", "Caddyfile"),
        ("infra/deployment/server/systemd/netvisor-backup-retention.service", "systemd/netvisor-backup-retention.service"),
        ("infra/deployment/server/systemd/netvisor-backup-retention.timer", "systemd/netvisor-backup-retention.timer"),
    ],
    "agent": [
        ("agent", "agent"),
        ("packet_engine", "packet_engine"),
        ("proto", "proto"),
        ("intel", "intel"),
        ("engine", "engine"),
        ("security", "security"),
        ("collector", "collector"),
        ("config/agent.json", "config/agent.json"),
        ("requirements-agent.txt", "requirements.txt"),
        ("run_agent.py", "run_agent.py"),
        ("scripts/run_agent.py", "scripts/run_agent.py"),
        ("scripts/launch_personal_chrome_dpi.cmd", "scripts/launch_personal_chrome_dpi.cmd"),
        ("infra/deployment/agent/systemd/netvisor-agent.service", "systemd/netvisor-agent.service"),
        ("infra/deployment/agent/README.md", "README.md"),
        ("infra/deployment/agent/.env.example", ".env.example"),
    ],
    "gateway": [
        ("gateway", "gateway"),
        ("packet_engine", "packet_engine"),
        ("proto", "proto"),
        ("intel", "intel"),
        ("engine", "engine"),
        ("security", "security"),
        ("collector", "collector"),
        ("requirements-gateway.txt", "requirements.txt"),
        ("run_gateway.py", "run_gateway.py"),
        ("scripts/run_gateway.py", "scripts/run_gateway.py"),
        ("infra/deployment/gateway/systemd/netvisor-gateway.service", "systemd/netvisor-gateway.service"),
        ("infra/deployment/gateway/README.md", "README.md"),
        ("infra/deployment/gateway/.env.example", ".env.example"),
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
        # Try to use npm from node_modules first (installed by npm ci in CI), then fall back to system PATH
        npm_cmd = None
        node_modules_npm = PROJECT_ROOT / "frontend" / "node_modules" / ".bin" / "npm"
        
        if node_modules_npm.exists():
            npm_cmd = str(node_modules_npm)
        else:
            npm_cmd = shutil.which("npm")
        
        if npm_cmd is None:
            raise FileNotFoundError("npm not found in PATH or node_modules/.bin")
        
        subprocess.run([npm_cmd, "run", "build"], cwd=frontend_root, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(f"[ERROR] Failed to build frontend: {exc}", file=sys.stderr)
        raise FileNotFoundError("npm is required to build the server bundle frontend asset") from exc

    if not dist_index.exists():
        raise FileNotFoundError("frontend build completed but frontend/dist/index.html is still missing")


def copy_item(source_rel: str, destination_rel: str, bundle_root: Path) -> None:
    source = PROJECT_ROOT / source_rel
    destination = bundle_root / destination_rel

    if not source.exists():
        raise FileNotFoundError(f"Required bundle asset is missing: {source}")

    if (
        source.name == ".env"
        or (source.name.startswith(".env.") and source.name != ".env.example")
        or source.suffix in {".session", ".db"}
    ):
        raise ValueError(f"Refusing to package secret/runtime artifact into deploy bundle: {source_rel}")

    destination.parent.mkdir(parents=True, exist_ok=True)

    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True, ignore=IGNORE_PATTERNS)
    else:
        shutil.copy2(source, destination)


def ensure_keys(keys_dir: Path) -> None:
    keys_dir.mkdir(parents=True, exist_ok=True)
    for prefix in ("dev", "prod"):
        private_path = keys_dir / f"{prefix}_signing_key.pem"
        public_path = keys_dir / f"{prefix}_public_key.pem"
        if not private_path.exists() or not public_path.exists():
            print(f"[*] Generating Ed25519 key pair for channel '{prefix}'...")
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            private_path.write_bytes(private_pem)
            public_path.write_bytes(public_pem)


def get_git_commit(project_root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=project_root,
            text=True,
            stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "unknown"


def sign_agent_bundle(bundle_root: Path, keys_dir: Path, channel: str) -> None:
    private_key_path = keys_dir / f"{channel}_signing_key.pem"
    public_key_path = keys_dir / f"{channel}_public_key.pem"
    
    if not private_key_path.exists() or not public_key_path.exists():
        raise FileNotFoundError(f"Signing keys not found for channel: {channel}")
        
    private_key_bytes = private_key_path.read_bytes()
    public_key_pem = public_key_path.read_text(encoding="utf-8")
    
    # 1. Write the public key file inside agent/security/
    dest_pub_key = bundle_root / "agent" / "security" / "agent_public_key.pem"
    dest_pub_key.parent.mkdir(parents=True, exist_ok=True)
    dest_pub_key.write_text(public_key_pem, encoding="utf-8")
    
    # 2. Embed public key in integrity.py inside the bundle
    integrity_py_path = bundle_root / "agent" / "security" / "integrity.py"
    if integrity_py_path.exists():
        content = integrity_py_path.read_text(encoding="utf-8")
        placeholder = "EMBEDDED_PUBLIC_KEY: str | None = None"
        if placeholder in content:
            escaped_pem = public_key_pem.replace('"""', '\\"\\"\\"')
            replacement = f'EMBEDDED_PUBLIC_KEY: str | None = """{escaped_pem}"""'
            content = content.replace(placeholder, replacement)
            integrity_py_path.write_text(content, encoding="utf-8")
            print(f"[+] Embedded {channel} public key directly in integrity.py")
        else:
            print("[WARNING] Could not find EMBEDDED_PUBLIC_KEY placeholder in integrity.py")
            
    # 3. Build manifest
    excluded_paths = {
        "manifest.json",
        "manifest.sig",
        "config/agent.json",
        ".env",
        ".env.example",
        "README.md",
    }
    
    files_manifest: dict[str, str] = {}
    for root, _, files in os.walk(bundle_root):
        root_path = Path(root)
        for file in files:
            file_path = root_path / file
            rel_path = file_path.relative_to(bundle_root).as_posix()
            
            # Exclusion rules
            normalized_rel = rel_path.replace("\\", "/")
            if normalized_rel in excluded_paths:
                continue
            parts = normalized_rel.split("/")
            if "systemd" in parts or "__pycache__" in parts or "runtime" in parts or "tmp" in parts:
                continue
            if rel_path.endswith((".pyc", ".pyo", ".log", ".csv", ".db")):
                continue
                
            # Compute sha256
            h = hashlib.sha256()
            with file_path.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            files_manifest[rel_path] = h.hexdigest()
            
    manifest_data = {
        "version": "v3.0-hybrid",
        "build_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "git_commit": get_git_commit(PROJECT_ROOT),
        "channel": channel,
        "files": files_manifest
    }
    
    manifest_bytes = json.dumps(manifest_data, sort_keys=True).encode("utf-8")
    (bundle_root / "manifest.json").write_bytes(manifest_bytes)
    
    # 4. Sign manifest
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    sig_bytes = private_key.sign(manifest_bytes)
    (bundle_root / "manifest.sig").write_bytes(sig_bytes)
    
    print(f"[+] Signed agent bundle manifest ({len(files_manifest)} files) for channel: {channel}")


def build_bundle(bundle_name: str, output_root: Path, channel: str = "dev") -> Path:
    bundle_root = output_root / bundle_name
    if bundle_root.exists():
        shutil.rmtree(bundle_root)

    bundle_root.mkdir(parents=True, exist_ok=True)
    if bundle_name == "server":
        ensure_server_frontend_dist()

    for source_rel, destination_rel in BUNDLES[bundle_name]:
        copy_item(source_rel, destination_rel, bundle_root)

    for secret_pattern in (".env", ".env.example.bak", "*.session", "*.db"):
        if any(bundle_root.rglob(secret_pattern)):
            raise ValueError(f"Bundle '{bundle_name}' still contains forbidden artifacts matching: {secret_pattern}")

    if bundle_name == "agent":
        keys_dir = PROJECT_ROOT / "keys"
        ensure_keys(keys_dir)
        sign_agent_bundle(bundle_root, keys_dir, channel)

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
        "--channel",
        choices=["dev", "prod"],
        default="dev",
        help="Release channel to build for (dev or prod). Determines the code signing keys used.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    validate_bundle_sources()
    output_root = args.output.resolve()
    roles = args.roles or sorted(BUNDLES.keys())
    channel = args.channel

    output_root.mkdir(parents=True, exist_ok=True)

    print(f"[*] Building NetVisor deploy bundles for channel '{channel}' into: {output_root}")
    for role in roles:
        bundle_root = build_bundle(role, output_root, channel=channel)
        print(f"[+] Built {role} bundle: {bundle_root}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
