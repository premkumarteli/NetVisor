from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
import pytest
from fastapi import HTTPException

from app.services.auth_service import auth_service
from app.core.config import settings


class RefreshTokenCursor:
    def __init__(self, conn, dictionary=True):
        self.conn = conn
        self.dictionary = dictionary
        self.last_query = ""
        self.rowcount = 0
        self._result = None

    def execute(self, query, params=None):
        self.last_query = " ".join(query.split())
        self.params = params
        self._result = None
        
        # INSERT INTO user_refresh_tokens
        if "INSERT INTO user_refresh_tokens" in self.last_query:
            user_id, token_hash, family_id, expires_at, ip_address, user_agent = params
            self.conn.tokens[token_hash] = {
                "id": len(self.conn.tokens) + 1,
                "user_id": user_id,
                "token_hash": token_hash,
                "family_id": family_id,
                "expires_at": expires_at,
                "created_at": datetime.now(),
                "last_used_at": None,
                "revoked": 0,
                "revoked_reason": None,
                "ip_address": ip_address,
                "user_agent": user_agent,
            }
            self.rowcount = 1
            return

        # SELECT * FROM user_refresh_tokens WHERE token_hash = %s
        if "SELECT * FROM user_refresh_tokens WHERE token_hash = %s" in self.last_query:
            token_hash = params[0]
            self._result = self.conn.tokens.get(token_hash)
            return

        # UPDATE user_refresh_tokens SET revoked = 1, revoked_reason = 'replay_detected' WHERE family_id = %s
        if "UPDATE user_refresh_tokens SET revoked = 1, revoked_reason = 'replay_detected' WHERE family_id = %s" in self.last_query:
            family_id = params[0]
            updated = 0
            for t in self.conn.tokens.values():
                if t["family_id"] == family_id and t["revoked"] == 0:
                    t["revoked"] = 1
                    t["revoked_reason"] = "replay_detected"
                    updated += 1
            self.rowcount = updated
            return

        # UPDATE user_refresh_tokens SET revoked = 1, revoked_reason = 'rotation'
        if "UPDATE user_refresh_tokens SET revoked = 1, revoked_reason = 'rotation'" in self.last_query:
            last_used_at, row_id = params
            updated = 0
            for t in self.conn.tokens.values():
                if t["id"] == row_id:
                    t["revoked"] = 1
                    t["revoked_reason"] = "rotation"
                    t["last_used_at"] = last_used_at
                    updated += 1
            self.rowcount = updated
            return

        # UPDATE user_refresh_tokens SET revoked = 1, revoked_reason = %s, last_used_at = %s WHERE token_hash = %s
        if "UPDATE user_refresh_tokens SET revoked = 1, revoked_reason = %s, last_used_at = %s WHERE token_hash = %s" in self.last_query:
            reason, last_used_at, token_hash = params
            updated = 0
            for t in self.conn.tokens.values():
                if t["token_hash"] == token_hash and t["revoked"] == 0:
                    t["revoked"] = 1
                    t["revoked_reason"] = reason
                    t["last_used_at"] = last_used_at
                    updated += 1
            self.rowcount = updated
            return

        # DELETE FROM user_refresh_tokens WHERE expires_at < %s
        if "DELETE FROM user_refresh_tokens WHERE expires_at < %s" in self.last_query:
            cutoff = params[0]
            initial_count = len(self.conn.tokens)
            self.conn.tokens = {k: v for k, v in self.conn.tokens.items() if v["expires_at"] >= cutoff}
            self.rowcount = initial_count - len(self.conn.tokens)
            return

    def fetchone(self):
        return self._result

    def close(self):
        pass


class RefreshTokenConnection:
    def __init__(self):
        self.tokens = {}
        self.committed = False
        self.rolled_back = False

    def cursor(self, dictionary=True):
        return RefreshTokenCursor(self, dictionary=dictionary)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


def test_create_refresh_token():
    conn = RefreshTokenConnection()
    token, expires_at = auth_service.create_refresh_token(
        conn,
        user_id="user-123",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0",
    )
    
    assert isinstance(token, str)
    assert len(token) == 64  # token_hex(32) produces 64 character hex string
    assert conn.committed is True
    
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert token_hash in conn.tokens
    
    saved = conn.tokens[token_hash]
    assert saved["user_id"] == "user-123"
    assert saved["ip_address"] == "192.168.1.100"
    assert saved["user_agent"] == "Mozilla/5.0"
    assert saved["revoked"] == 0
    assert saved["revoked_reason"] is None


def test_rotate_refresh_token():
    conn = RefreshTokenConnection()
    
    # 1. Create a refresh token
    token, expires_at = auth_service.create_refresh_token(
        conn,
        user_id="user-123",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0",
    )
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    family_id = conn.tokens[token_hash]["family_id"]
    
    # 2. Rotate it
    new_token, user_id, new_expires = auth_service.rotate_refresh_token(
        conn,
        token=token,
        ip_address="192.168.1.101",
        user_agent="Mozilla/5.0 Updated",
    )
    
    assert new_token != token
    assert user_id == "user-123"
    
    # Verify old token is consumed/revoked
    assert conn.tokens[token_hash]["revoked"] == 1
    assert conn.tokens[token_hash]["revoked_reason"] == "rotation"
    assert conn.tokens[token_hash]["last_used_at"] is not None
    
    # Verify new token is created in the same family
    new_hash = hashlib.sha256(new_token.encode("utf-8")).hexdigest()
    new_saved = conn.tokens[new_hash]
    assert new_saved["family_id"] == family_id
    assert new_saved["user_id"] == "user-123"
    assert new_saved["ip_address"] == "192.168.1.101"
    assert new_saved["user_agent"] == "Mozilla/5.0 Updated"
    assert new_saved["revoked"] == 0


def test_replay_detection_revokes_entire_family():
    conn = RefreshTokenConnection()
    
    # 1. Create token A
    token_a, _ = auth_service.create_refresh_token(conn, user_id="user-123")
    hash_a = hashlib.sha256(token_a.encode("utf-8")).hexdigest()
    family_id = conn.tokens[hash_a]["family_id"]
    
    # 2. Rotate to token B
    token_b, _, _ = auth_service.rotate_refresh_token(conn, token=token_a)
    hash_b = hashlib.sha256(token_b.encode("utf-8")).hexdigest()
    
    # At this point, token A is revoked, token B is active
    assert conn.tokens[hash_a]["revoked"] == 1
    assert conn.tokens[hash_b]["revoked"] == 0
    
    # 3. Simulate replay attack: Attacker attempts to rotate the already revoked token A
    with pytest.raises(HTTPException) as exc_info:
        auth_service.rotate_refresh_token(conn, token=token_a)
        
    assert exc_info.value.status_code == 401
    assert "Refresh token has already been used" in exc_info.value.detail
    
    # Verify that the entire family (including token B) is now revoked!
    assert conn.tokens[hash_b]["revoked"] == 1
    assert conn.tokens[hash_b]["revoked_reason"] == "replay_detected"


def test_revoke_refresh_token():
    conn = RefreshTokenConnection()
    token, _ = auth_service.create_refresh_token(conn, user_id="user-123")
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    
    assert conn.tokens[token_hash]["revoked"] == 0
    
    auth_service.revoke_refresh_token(conn, token, reason="logout")
    
    assert conn.tokens[token_hash]["revoked"] == 1
    assert conn.tokens[token_hash]["revoked_reason"] == "logout"
    assert conn.tokens[token_hash]["last_used_at"] is not None


def test_cleanup_expired_tokens():
    conn = RefreshTokenConnection()
    
    # Create an unexpired token
    unexpired_token, _ = auth_service.create_refresh_token(conn, user_id="user-123")
    unexpired_hash = hashlib.sha256(unexpired_token.encode("utf-8")).hexdigest()
    
    # Create an expired token by setting expires_at in the past
    expired_token, _ = auth_service.create_refresh_token(conn, user_id="user-123")
    expired_hash = hashlib.sha256(expired_token.encode("utf-8")).hexdigest()
    conn.tokens[expired_hash]["expires_at"] = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
    
    # Verify both exist before cleanup
    assert len(conn.tokens) == 2
    
    # Perform cleanup
    deleted_count = auth_service.cleanup_expired_tokens(conn)
    
    assert deleted_count == 1
    assert len(conn.tokens) == 1
    assert unexpired_hash in conn.tokens
    assert expired_hash not in conn.tokens


# API Endpoint Tests

from fastapi import Response
from app.api import auth as auth_api
from types import SimpleNamespace
import asyncio

def _run(awaitable):
    return asyncio.run(awaitable)

def _get_cookie_dict(response: Response) -> dict:
    cookies = {}
    for header in response.headers.getlist("set-cookie"):
        parts = header.split(";")[0].split("=")
        if len(parts) == 2:
            cookies[parts[0].strip()] = parts[1].strip()
    return cookies

def test_login_sets_refresh_cookie(monkeypatch):
    conn = RefreshTokenConnection()
    user = {
        "id": "user-1",
        "username": "alice",
        "email": "alice@example.com",
        "role": "org_admin",
        "organization_id": "org-1",
    }

    monkeypatch.setattr(auth_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(auth_api.auth_service, "authenticate", lambda *_args: user)
    monkeypatch.setattr(auth_api.metrics_service, "increment", lambda *args, **kwargs: None)
    monkeypatch.setattr(auth_api.audit_service, "log_auth_attempt", lambda *args, **kwargs: None)
    
    response = Response()
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        url=SimpleNamespace(scheme="http"),
        headers={"User-Agent": "Mozilla/5.0"},
    )
    form_data = SimpleNamespace(username="alice", password="secret123")

    payload = _run(auth_api.login(request, response, form_data, _rate_limited=True))

    assert payload["authenticated"] is True
    cookies = _get_cookie_dict(response)
    assert settings.AUTH_COOKIE_NAME in cookies
    assert settings.REFRESH_COOKIE_NAME in cookies
    
    token = cookies[settings.REFRESH_COOKIE_NAME]
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert token_hash in conn.tokens


def test_refresh_session_rotates_cookies(monkeypatch):
    conn = RefreshTokenConnection()
    
    user = {
        "id": "user-1",
        "username": "alice",
        "email": "alice@example.com",
        "role": "org_admin",
        "organization_id": "org-1",
        "status": "active",
        "locked_until": None,
    }
    token_plain, _ = auth_service.create_refresh_token(conn, user_id="user-1")
    old_hash = hashlib.sha256(token_plain.encode("utf-8")).hexdigest()
    
    monkeypatch.setattr(auth_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(auth_api.auth_service, "get_user_by_id", lambda *_args: user)
    monkeypatch.setattr(auth_api.audit_service, "log_auth_attempt", lambda *args, **kwargs: None)

    request = SimpleNamespace(
        cookies={settings.REFRESH_COOKIE_NAME: token_plain},
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"User-Agent": "Mozilla/5.0"},
        url=SimpleNamespace(scheme="http"),
    )
    response = Response()

    payload = _run(auth_api.refresh_session(request, response))
    
    assert payload["status"] == "success"
    cookies = _get_cookie_dict(response)
    assert settings.AUTH_COOKIE_NAME in cookies
    assert settings.REFRESH_COOKIE_NAME in cookies
    
    new_token = cookies[settings.REFRESH_COOKIE_NAME]
    assert new_token != token_plain
    
    assert conn.tokens[old_hash]["revoked"] == 1
    new_hash = hashlib.sha256(new_token.encode("utf-8")).hexdigest()
    assert new_hash in conn.tokens
    assert conn.tokens[new_hash]["revoked"] == 0


def test_refresh_session_replay_detected_audit_logged(monkeypatch):
    conn = RefreshTokenConnection()
    
    user = {
        "id": "user-1",
        "username": "alice",
        "role": "org_admin",
        "organization_id": "org-1",
        "status": "active",
    }
    
    token_plain, _ = auth_service.create_refresh_token(conn, user_id="user-1")
    old_hash = hashlib.sha256(token_plain.encode("utf-8")).hexdigest()
    conn.tokens[old_hash]["revoked"] = 1
    
    monkeypatch.setattr(auth_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(auth_api.auth_service, "get_user_by_id", lambda *_args: user)
    
    audit_logs = []
    monkeypatch.setattr(auth_api.audit_service, "log_auth_attempt", lambda *args, **kwargs: audit_logs.append((args, kwargs)))

    request = SimpleNamespace(
        cookies={settings.REFRESH_COOKIE_NAME: token_plain},
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"User-Agent": "Mozilla/5.0"},
        url=SimpleNamespace(scheme="http"),
    )
    response = Response()

    with pytest.raises(HTTPException) as exc_info:
        _run(auth_api.refresh_session(request, response))
        
    assert exc_info.value.status_code == 401
    
    assert len(audit_logs) == 1
    args, kwargs = audit_logs[0]
    assert kwargs.get("action") == "refresh_token_replay_detected"
    assert "Replay attack detected" in kwargs.get("details", "")


def test_logout_revokes_token_and_clears_cookies(monkeypatch):
    conn = RefreshTokenConnection()
    token_plain, _ = auth_service.create_refresh_token(conn, user_id="user-1")
    token_hash = hashlib.sha256(token_plain.encode("utf-8")).hexdigest()
    
    monkeypatch.setattr(auth_api, "get_db_connection", lambda: conn)
    monkeypatch.setattr(auth_api.audit_service, "log_auth_attempt", lambda *args, **kwargs: None)
    
    request = SimpleNamespace(
        cookies={
            settings.REFRESH_COOKIE_NAME: token_plain,
            settings.AUTH_COOKIE_NAME: "dummy-access-token"
        },
        client=SimpleNamespace(host="127.0.0.1"),
        url=SimpleNamespace(scheme="http"),
    )
    response = Response()
    
    payload = _run(auth_api.logout(request, response))
    
    assert payload["status"] == "ok"
    assert conn.tokens[token_hash]["revoked"] == 1
    assert conn.tokens[token_hash]["revoked_reason"] == "logout"
    
    cookie_headers = response.headers.getlist("set-cookie")
    auth_cleared = False
    refresh_cleared = False
    for h in cookie_headers:
        if settings.AUTH_COOKIE_NAME in h and "Max-Age=0" in h:
            auth_cleared = True
        if settings.REFRESH_COOKIE_NAME in h and "Max-Age=0" in h:
            refresh_cleared = True
            
    assert auth_cleared is True
    assert refresh_cleared is True
