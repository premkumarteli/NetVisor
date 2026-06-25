from __future__ import annotations

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("netvisor.agent_integrity")

# Pluggable placeholder that scripts/build_deploy_bundles.py will replace with PEM string at build time
EMBEDDED_PUBLIC_KEY: str | None = None

EXCLUDED_PATHS = {
    "manifest.json",
    "manifest.sig",
    "config/agent.json",
    ".env",
    ".env.example",
    "README.md",
}


def _compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_excluded(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    if normalized in EXCLUDED_PATHS:
        return True
    parts = normalized.split("/")
    if "systemd" in parts or "__pycache__" in parts or "runtime" in parts or "tmp" in parts:
        return True
    if rel_path.endswith((".pyc", ".pyo", ".log", ".csv", ".db")):
        return True
    return False


def verify_agent_code_integrity(bundle_root: Path) -> dict[str, Any]:
    """
    Verifies the cryptographic signature of the agent code manifest and asserts file integrity.
    Returns a status dict:
      {
         "status": "verified" | "unsigned_dev" | "failed",
         "findings": [{"severity": "critical"|"warning", "code": str, "message": str}],
         "manifest_hash": str | None,
         "metadata": dict
      }
    """
    findings: list[dict[str, str]] = []
    
    # 1. Resolve Public Key
    public_key_pem = EMBEDDED_PUBLIC_KEY
    if not public_key_pem:
        # Development fallback: try loading from workspace root
        dev_key_path = bundle_root / "keys" / "dev_public_key.pem"
        if not dev_key_path.exists():
            # Try ascending directory tree to find dev_public_key.pem in root keys/
            dev_key_path = bundle_root.parent / "keys" / "dev_public_key.pem"
            if not dev_key_path.exists():
                dev_key_path = bundle_root.parent.parent / "keys" / "dev_public_key.pem"

        if dev_key_path.exists():
            try:
                public_key_pem = dev_key_path.read_text(encoding="utf-8")
            except Exception as e:
                logger.warning("Failed to load dev public key from %s: %s", dev_key_path, e)

    # 2. Check if manifest files exist
    manifest_path = bundle_root / "manifest.json"
    sig_path = bundle_root / "manifest.sig"

    if not manifest_path.exists() or not sig_path.exists():
        if os.getenv("NETVISOR_REQUIRE_SIGNATURE", "false").strip().lower() in {"1", "true", "yes", "on"}:
            findings.append({
                "severity": "critical",
                "code": "missing_manifest",
                "message": "Signature manifest or signature file is missing, and signatures are strictly required."
            })
            return {"status": "failed", "findings": findings, "manifest_hash": None, "metadata": {}}
        
        findings.append({
            "severity": "warning",
            "code": "unsigned_mode",
            "message": "Running in unsigned development mode. Code integrity is not enforced."
        })
        return {"status": "unsigned_dev", "findings": findings, "manifest_hash": None, "metadata": {}}

    if not public_key_pem:
        findings.append({
            "severity": "critical",
            "code": "missing_public_key",
            "message": "No embedded public key or local keys/dev_public_key.pem available for verification."
        })
        return {"status": "failed", "findings": findings, "manifest_hash": None, "metadata": {}}

    # 3. Load Public Key & Verify Signature
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        findings.append({
            "severity": "critical",
            "code": "invalid_public_key",
            "message": f"Verification public key is malformed: {exc}"
        })
        return {"status": "failed", "findings": findings, "manifest_hash": None, "metadata": {}}

    try:
        manifest_bytes = manifest_path.read_bytes()
        sig_bytes = sig_path.read_bytes()
    except Exception as exc:
        findings.append({
            "severity": "critical",
            "code": "read_error",
            "message": f"Failed to read signature or manifest: {exc}"
        })
        return {"status": "failed", "findings": findings, "manifest_hash": None, "metadata": {}}

    try:
        public_key.verify(sig_bytes, manifest_bytes)
    except Exception:
        findings.append({
            "severity": "critical",
            "code": "signature_mismatch",
            "message": "Code manifest signature verification failed. The manifest has been modified or signed with a different key."
        })
        return {"status": "failed", "findings": findings, "manifest_hash": None, "metadata": {}}

    # 4. Parse Manifest
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as exc:
        findings.append({
            "severity": "critical",
            "code": "malformed_manifest",
            "message": f"Manifest JSON parsing failed: {exc}"
        })
        return {"status": "failed", "findings": findings, "manifest_hash": None, "metadata": {}}

    manifest_files = manifest.get("files") or {}
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    metadata = {
        "version": manifest.get("version", "unknown"),
        "build_time": manifest.get("build_time", "unknown"),
        "git_commit": manifest.get("git_commit", "unknown"),
        "channel": manifest.get("channel", "unknown"),
    }

    # 5. Scan Files and Compute Handoffs
    local_hashes: dict[str, str] = {}
    for root, _, files in os.walk(bundle_root):
        root_path = Path(root)
        for file in files:
            file_path = root_path / file
            try:
                rel_path = file_path.relative_to(bundle_root).as_posix()
            except ValueError:
                continue
            if _is_excluded(rel_path):
                continue
            try:
                local_hashes[rel_path] = _compute_sha256(file_path)
            except Exception as exc:
                findings.append({
                    "severity": "critical",
                    "code": "hash_error",
                    "message": f"Could not compute hash for {rel_path}: {exc}"
                })

    # 6. Compare Hashes
    # Case A: Modified or Deleted Files
    for rel_path, expected_hash in manifest_files.items():
        if rel_path not in local_hashes:
            findings.append({
                "severity": "critical",
                "code": "file_deleted",
                "message": f"Required agent file is missing: {rel_path}"
            })
        elif local_hashes[rel_path] != expected_hash:
            findings.append({
                "severity": "critical",
                "code": "file_modified",
                "message": f"Agent file has been modified: {rel_path}"
            })

    # Case B: Added/Unauthorized Files
    for rel_path in local_hashes:
        if rel_path not in manifest_files:
            findings.append({
                "severity": "critical",
                "code": "file_added",
                "message": f"Unauthorized file added to agent bundle: {rel_path}"
            })

    if findings:
        return {"status": "failed", "findings": findings, "manifest_hash": manifest_hash, "metadata": metadata}

    return {"status": "verified", "findings": [], "manifest_hash": manifest_hash, "metadata": metadata}
