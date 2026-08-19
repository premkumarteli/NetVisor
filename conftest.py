from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from pathlib import Path

import pytest

from backend.core.config import Settings
from backend.core.security import set_settings

# Set test environment variables BEFORE any other imports
# This ensures Settings reads the correct values when first instantiated
os.environ["NETVISOR_JWT_ALGORITHM"] = "HS256"
os.environ["NETVISOR_SECRET_KEY"] = "test-secret-key-that-is-long-enough-for-hs256-testing-purposes-only"

_WORKSPACE_TMP_ROOT: Path | None = None


def _configure_pytest_tempdir() -> None:
    # Keep pytest temporary directories inside the workspace so Windows temp ACLs
    # or stale numbered-dir cleanup do not break tmp_path-based tests.
    global _WORKSPACE_TMP_ROOT
    workspace_tmp = Path(__file__).resolve().parent / ".pytest_tmp" / f"run-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    workspace_tmp.mkdir(parents=True, exist_ok=True)
    _WORKSPACE_TMP_ROOT = workspace_tmp
    for key in ("TMP", "TEMP", "TMPDIR"):
        os.environ[key] = str(workspace_tmp)
    tempfile.tempdir = str(workspace_tmp)


@pytest.fixture(scope="function", autouse=True)
def test_settings(monkeypatch):
    """Configure test settings with HS256 for JWT tokens."""
    monkeypatch.setenv("NETVISOR_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("NETVISOR_SECRET_KEY", "test-secret-key-that-is-long-enough-for-hs256-testing-purposes-only")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-that-is-long-enough-for-hs256-testing-purposes-only")
    monkeypatch.delenv("NETVISOR_JWT_PRIVATE_KEY_PATH", raising=False)
    monkeypatch.delenv("NETVISOR_JWT_PUBLIC_KEY_PATH", raising=False)
    monkeypatch.delenv("NETVISOR_JWT_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("NETVISOR_JWT_PUBLIC_KEY", raising=False)

    test_settings = Settings(
        JWT_ALGORITHM="HS256",
        SECRET_KEY="test-secret-key-that-is-long-enough-for-hs256-testing-purposes-only",
        NETVISOR_SECRET_KEY="test-secret-key-that-is-long-enough-for-hs256-testing-purposes-only",
    )
    set_settings(test_settings)
    yield test_settings
    # Reset to default settings after tests
    set_settings(None)



_configure_pytest_tempdir()


@pytest.fixture
def tmp_path():
    # Avoid pytest's own numbered temp factory on this machine; it hits ACL issues
    # in the default temp roots. A plain workspace-local path is enough for these tests.
    root = Path(__file__).resolve().parent / ".pytest_tmp" / f"manual-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    root.mkdir(parents=True, exist_ok=False)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def pytest_sessionfinish(session, exitstatus):
    workspace_root = Path(__file__).resolve().parent
    for path in workspace_root.glob(".pytest_tmp*"):
        shutil.rmtree(path, ignore_errors=True)
    if _WORKSPACE_TMP_ROOT is not None:
        shutil.rmtree(_WORKSPACE_TMP_ROOT, ignore_errors=True)
