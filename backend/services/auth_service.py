from typing import Optional
from datetime import datetime, timedelta, timezone
from ..core.security import verify_password, get_password_hash
from ..core.config import settings
import uuid
import logging
import secrets
import hashlib
from fastapi import HTTPException, status

logger = logging.getLogger("netvisor.auth")

class AuthService:
    def _parse_timestamp(self, value):
        if value is None or value == "":
            return None
        if isinstance(value, datetime):
            return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
                try:
                    return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return None

    def _is_locked(self, user: dict) -> bool:
        locked_until = self._parse_timestamp(user.get("locked_until"))
        return bool(locked_until and locked_until > datetime.now(timezone.utc))

    def _record_failed_login(self, db_conn, user_id: str) -> None:
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                UPDATE users
                SET
                    failed_login_count = COALESCE(failed_login_count, 0) + 1,
                    locked_until = CASE
                        WHEN COALESCE(failed_login_count, 0) + 1 >= %s
                            THEN DATE_ADD(UTC_TIMESTAMP(), INTERVAL %s MINUTE)
                        ELSE locked_until
                    END
                WHERE id = %s
                """,
                (
                    max(int(settings.LOGIN_LOCKOUT_THRESHOLD or 5), 1),
                    max(int(settings.LOGIN_LOCKOUT_MINUTES or 15), 1),
                    user_id,
                ),
            )
            db_conn.commit()
        except Exception:
            db_conn.rollback()
        finally:
            cursor.close()

    def _record_successful_login(self, db_conn, user_id: str) -> None:
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                UPDATE users
                SET failed_login_count = 0, locked_until = NULL
                WHERE id = %s
                """,
                (user_id,),
            )
            db_conn.commit()
        except Exception:
            db_conn.rollback()
        finally:
            cursor.close()

    def authenticate(self, db_conn, username, password) -> Optional[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            login_identifier = str(username or "").strip()
            cursor.execute(
                "SELECT * FROM users WHERE username = %s OR email = %s LIMIT 1",
                (login_identifier, login_identifier),
            )
            user = cursor.fetchone()
            if not user:
                return None
            if str(user.get("status") or "active").lower() == "disabled":
                return None
            if self._is_locked(user):
                return None
            if verify_password(password, user["password"]):
                self._record_successful_login(db_conn, user["id"])
                user["failed_login_count"] = 0
                user["locked_until"] = None
                return user
            if user.get("id"):
                self._record_failed_login(db_conn, user["id"])
            return None
        finally:
            cursor.close()

    def create_user(self, db_conn, user_in) -> Optional[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (user_in.username, user_in.email))
            if cursor.fetchone():
                return None
            
            # Get default organization
            cursor.execute("SELECT id FROM organizations WHERE name = 'Default Organization' LIMIT 1")
            org = cursor.fetchone()
            default_org_id = org["id"] if org else None

            user_id = str(uuid.uuid4())
            hashed_password = get_password_hash(user_in.password)
            
            cursor.execute(
                "INSERT INTO users (id, username, password, email, role, organization_id) VALUES (%s, %s, %s, %s, %s, %s)",
                (user_id, user_in.username, hashed_password, user_in.email, "viewer", default_org_id)
            )
            db_conn.commit()
            return {
                "id": user_id,
                "username": user_in.username,
                "email": user_in.email,
                "role": "viewer",
                "organization_id": default_org_id,
            }
        finally:
            cursor.close()

    def get_user_by_id(self, db_conn, user_id: str) -> Optional[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM users WHERE id = %s LIMIT 1", (user_id,))
            return cursor.fetchone()
        finally:
            cursor.close()

    def count_users(self, db_conn) -> int:
        cursor = db_conn.cursor()
        try:
            cursor.execute("SELECT COUNT(*) FROM users")
            row = cursor.fetchone()
            return int(row[0] if row else 0)
        finally:
            cursor.close()

    def create_refresh_token(self, db_conn, user_id: str, family_id: str = None, ip_address: str = None, user_agent: str = None) -> tuple[str, datetime]:
        cursor = db_conn.cursor()
        try:
            token = secrets.token_hex(32)
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            if not family_id:
                family_id = str(uuid.uuid4())
            
            days = max(int(settings.REFRESH_TOKEN_DAYS or 7), 1)
            expires_at = datetime.now(timezone.utc) + timedelta(days=days)
            expires_at_naive = expires_at.replace(tzinfo=None)

            cursor.execute(
                """
                INSERT INTO user_refresh_tokens (user_id, token_hash, family_id, expires_at, ip_address, user_agent)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (user_id, token_hash, family_id, expires_at_naive, ip_address, user_agent),
            )
            db_conn.commit()
            return token, expires_at
        except Exception:
            db_conn.rollback()
            raise
        finally:
            cursor.close()

    def rotate_refresh_token(self, db_conn, token: str, ip_address: str = None, user_agent: str = None) -> tuple[str, str, datetime]:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT * FROM user_refresh_tokens WHERE token_hash = %s LIMIT 1",
                (token_hash,),
            )
            row = cursor.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token",
                )
            
            user_id = row["user_id"]
            family_id = row["family_id"]
            revoked = row["revoked"]
            expires_at = row["expires_at"]
            
            now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
            if expires_at < now_naive:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token expired",
                )
            
            if revoked:
                cursor.execute(
                    """
                    UPDATE user_refresh_tokens
                    SET revoked = 1, revoked_reason = 'replay_detected'
                    WHERE family_id = %s AND revoked = 0
                    """,
                    (family_id,),
                )
                db_conn.commit()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Security alert: Refresh token has already been used",
                )
            
            cursor.execute(
                """
                UPDATE user_refresh_tokens
                SET revoked = 1, revoked_reason = 'rotation', last_used_at = %s
                WHERE id = %s
                """,
                (now_naive, row["id"]),
            )
            
            new_token, new_expires = self.create_refresh_token(
                db_conn, user_id=user_id, family_id=family_id, ip_address=ip_address, user_agent=user_agent
            )
            
            return new_token, user_id, new_expires
        except Exception:
            db_conn.rollback()
            raise
        finally:
            cursor.close()

    def revoke_refresh_token(self, db_conn, token: str, reason: str = "logout") -> None:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        cursor = db_conn.cursor()
        try:
            now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
            cursor.execute(
                """
                UPDATE user_refresh_tokens
                SET revoked = 1, revoked_reason = %s, last_used_at = %s
                WHERE token_hash = %s AND revoked = 0
                """,
                (reason, now_naive, token_hash),
            )
            db_conn.commit()
        except Exception:
            db_conn.rollback()
            raise
        finally:
            cursor.close()

    def revoke_token_family_by_user(self, db_conn, user_id: str, reason: str = "admin_reset") -> None:
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                UPDATE user_refresh_tokens
                SET revoked = 1, revoked_reason = %s
                WHERE user_id = %s AND revoked = 0
                """,
                (reason, user_id),
            )
            db_conn.commit()
        except Exception:
            db_conn.rollback()
            raise
        finally:
            cursor.close()

    def cleanup_expired_tokens(self, db_conn) -> int:
        cursor = db_conn.cursor()
        try:
            now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
            cursor.execute(
                "DELETE FROM user_refresh_tokens WHERE expires_at < %s",
                (now_naive,),
            )
            deleted = cursor.rowcount
            db_conn.commit()
            return deleted
        except Exception:
            db_conn.rollback()
            raise
        finally:
            cursor.close()

auth_service = AuthService()
