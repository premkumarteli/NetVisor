from __future__ import annotations

import json
import os
import shutil
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import pytest
from agent.security.integrity import verify_agent_code_integrity


def _compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture
def temp_bundle(tmp_path):
    bundle_dir = tmp_path / "agent_bundle"
    bundle_dir.mkdir()
    
    # Create mock files
    (bundle_dir / "run_agent.py").write_text("print('mock agent')", encoding="utf-8")
    
    agent_dir = bundle_dir / "agent"
    agent_dir.mkdir()
    (agent_dir / "main.py").write_text("def run(): pass", encoding="utf-8")
    
    security_dir = agent_dir / "security"
    security_dir.mkdir()
    (security_dir / "integrity.py").write_text("EMBEDDED_PUBLIC_KEY: str | None = None", encoding="utf-8")
    
    shared_dir = bundle_dir / "shared"
    shared_dir.mkdir()
    (shared_dir / "utils.py").write_text("def helper(): pass", encoding="utf-8")
    
    return bundle_dir


def test_unsigned_dev_mode_by_default(temp_bundle, monkeypatch):
    monkeypatch.delenv("NETVISOR_REQUIRE_SIGNATURE", raising=False)
    result = verify_agent_code_integrity(temp_bundle)
    assert result["status"] == "unsigned_dev"
    assert any(f["code"] == "unsigned_mode" for f in result["findings"])


def test_signature_required_but_missing(temp_bundle, monkeypatch):
    monkeypatch.setenv("NETVISOR_REQUIRE_SIGNATURE", "true")
    result = verify_agent_code_integrity(temp_bundle)
    assert result["status"] == "failed"
    assert any(f["code"] == "missing_manifest" for f in result["findings"])


def test_valid_signed_bundle(temp_bundle, monkeypatch):
    monkeypatch.delenv("NETVISOR_REQUIRE_SIGNATURE", raising=False)
    
    # 1. Generate keys
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
    ).decode("utf-8")
    
    # Write public key to the bundle
    pub_key_path = temp_bundle / "agent" / "security" / "agent_public_key.pem"
    pub_key_path.write_text(public_pem, encoding="utf-8")
    
    # Mock embedding the public key
    integrity_py = temp_bundle / "agent" / "security" / "integrity.py"
    integrity_py.write_text(f'EMBEDDED_PUBLIC_KEY: str | None = """{public_pem}"""', encoding="utf-8")
    
    # 2. Build manifest
    files_to_hash = [
        "run_agent.py",
        "agent/main.py",
        "agent/security/integrity.py",
        "agent/security/agent_public_key.pem",
        "shared/utils.py"
    ]
    
    files_manifest = {}
    for rel_path in files_to_hash:
        files_manifest[rel_path] = _compute_sha256(temp_bundle / rel_path)
        
    manifest_data = {
        "version": "v3.0-test",
        "build_time": "2026-06-07T12:00:00Z",
        "git_commit": "abcdef",
        "channel": "dev",
        "files": files_manifest
    }
    
    manifest_bytes = json.dumps(manifest_data, sort_keys=True).encode("utf-8")
    (temp_bundle / "manifest.json").write_bytes(manifest_bytes)
    
    # 3. Sign manifest
    sig_bytes = private_key.sign(manifest_bytes)
    (temp_bundle / "manifest.sig").write_bytes(sig_bytes)
    
    # Load and mock embedded key in test module
    monkeypatch.setattr("agent.security.integrity.EMBEDDED_PUBLIC_KEY", public_pem)
    
    result = verify_agent_code_integrity(temp_bundle)
    assert result["status"] == "verified"
    assert len(result["findings"]) == 0
    assert result["metadata"]["version"] == "v3.0-test"


def test_modified_file_fails_verification(temp_bundle, monkeypatch):
    # Setup signed bundle
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    monkeypatch.setattr("agent.security.integrity.EMBEDDED_PUBLIC_KEY", public_pem)
    
    # Mock keys and files
    (temp_bundle / "agent" / "security" / "agent_public_key.pem").write_text(public_pem, encoding="utf-8")
    (temp_bundle / "agent" / "security" / "integrity.py").write_text(
        f'EMBEDDED_PUBLIC_KEY: str | None = """{public_pem}"""', encoding="utf-8"
    )
    
    files_to_hash = [
        "run_agent.py",
        "agent/main.py",
        "agent/security/integrity.py",
        "agent/security/agent_public_key.pem",
        "shared/utils.py"
    ]
    files_manifest = {rel_path: _compute_sha256(temp_bundle / rel_path) for rel_path in files_to_hash}
    
    manifest_bytes = json.dumps({"files": files_manifest}, sort_keys=True).encode("utf-8")
    (temp_bundle / "manifest.json").write_bytes(manifest_bytes)
    (temp_bundle / "manifest.sig").write_bytes(private_key.sign(manifest_bytes))
    
    # TAMPER: Modify shared/utils.py
    (temp_bundle / "shared" / "utils.py").write_text("def helper(): print('tampered')", encoding="utf-8")
    
    result = verify_agent_code_integrity(temp_bundle)
    assert result["status"] == "failed"
    assert any(f["code"] == "file_modified" and "shared/utils.py" in f["message"] for f in result["findings"])


def test_added_file_fails_verification(temp_bundle, monkeypatch):
    # Setup signed bundle
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    monkeypatch.setattr("agent.security.integrity.EMBEDDED_PUBLIC_KEY", public_pem)
    
    files_to_hash = ["run_agent.py", "agent/main.py", "agent/security/integrity.py", "shared/utils.py"]
    files_manifest = {rel_path: _compute_sha256(temp_bundle / rel_path) for rel_path in files_to_hash}
    
    manifest_bytes = json.dumps({"files": files_manifest}, sort_keys=True).encode("utf-8")
    (temp_bundle / "manifest.json").write_bytes(manifest_bytes)
    (temp_bundle / "manifest.sig").write_bytes(private_key.sign(manifest_bytes))
    
    # TAMPER: Add unauthorized backdoor.py
    (temp_bundle / "agent" / "backdoor.py").write_text("print('backdoor')", encoding="utf-8")
    
    result = verify_agent_code_integrity(temp_bundle)
    assert result["status"] == "failed"
    assert any(f["code"] == "file_added" and "agent/backdoor.py" in f["message"] for f in result["findings"])


def test_deleted_file_fails_verification(temp_bundle, monkeypatch):
    # Setup signed bundle
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    monkeypatch.setattr("agent.security.integrity.EMBEDDED_PUBLIC_KEY", public_pem)
    
    files_to_hash = ["run_agent.py", "agent/main.py", "agent/security/integrity.py", "shared/utils.py"]
    files_manifest = {rel_path: _compute_sha256(temp_bundle / rel_path) for rel_path in files_to_hash}
    
    manifest_bytes = json.dumps({"files": files_manifest}, sort_keys=True).encode("utf-8")
    (temp_bundle / "manifest.json").write_bytes(manifest_bytes)
    (temp_bundle / "manifest.sig").write_bytes(private_key.sign(manifest_bytes))
    
    # TAMPER: Delete shared/utils.py
    os.remove(temp_bundle / "shared" / "utils.py")
    
    result = verify_agent_code_integrity(temp_bundle)
    assert result["status"] == "failed"
    assert any(f["code"] == "file_deleted" and "shared/utils.py" in f["message"] for f in result["findings"])


def test_modified_signature_fails_verification(temp_bundle, monkeypatch):
    # Setup signed bundle
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    monkeypatch.setattr("agent.security.integrity.EMBEDDED_PUBLIC_KEY", public_pem)
    
    files_to_hash = ["run_agent.py", "agent/main.py", "agent/security/integrity.py", "shared/utils.py"]
    files_manifest = {rel_path: _compute_sha256(temp_bundle / rel_path) for rel_path in files_to_hash}
    
    manifest_bytes = json.dumps({"files": files_manifest}, sort_keys=True).encode("utf-8")
    (temp_bundle / "manifest.json").write_bytes(manifest_bytes)
    
    # TAMPER: Sign invalid data or corrupt signature
    (temp_bundle / "manifest.sig").write_bytes(b"invalid_signature_data_here_corrupted")
    
    result = verify_agent_code_integrity(temp_bundle)
    assert result["status"] == "failed"
    assert any(f["code"] == "signature_mismatch" for f in result["findings"])
