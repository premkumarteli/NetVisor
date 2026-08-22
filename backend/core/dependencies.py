from collections import deque
from fastapi import Request, HTTPException, Depends, status
from jose import JWTError
from pydantic import ValidationError
from datetime import datetime, timezone
from .config import settings
from .security import verify_access_token
from ..db.session import get_db, get_db_connection
from ..services.auth_service import auth_service
from ..services.metrics_service import metrics_service
import logging
import time
import threading

logger = logging.getLogger("netvisor.deps")

def _resolve_request_token(request: Request) -> str:
    cookie_token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    if cookie_token:
        return cookie_token

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


class SecurityContext(dict):
    def __init__(
        self,
        user_id: str | None = None,
        organization_id: str | None = None,
        role: str | None = None,
        permissions: list[str] | None = None,
        username: str | None = None,
        email: str | None = None,
        id: str | None = None,
        **kwargs,
    ):
        resolved_id = user_id if user_id is not None else id
        super().__init__(
            id=resolved_id,
            user_id=resolved_id,
            organization_id=organization_id,
            role=role,
            permissions=permissions or [],
            username=username,
            email=email,
            **kwargs,
        )

    @property
    def id(self) -> str | None:
        return self.get("id") or self.get("user_id")

    @property
    def user_id(self) -> str | None:
        return self.get("user_id") or self.get("id")

    @property
    def organization_id(self) -> str | None:
        return self.get("organization_id")

    @property
    def role(self) -> str | None:
        return self.get("role")

    @property
    def permissions(self) -> list[str]:
        return self.get("permissions", [])

    @property
    def username(self) -> str | None:
        return self.get("username")

    @property
    def email(self) -> str | None:
        return self.get("email")


def get_current_user(
    request: Request,
    conn = Depends(get_db),
):
    try:
        resolved_token = _resolve_request_token(request)
        payload = verify_access_token(resolved_token)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = auth_service.get_user_by_id(conn, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if str(user.get("status") or "active").lower() == "disabled":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is disabled",
            )
        locked_until = user.get("locked_until")
        if isinstance(locked_until, str):
            try:
                locked_until = datetime.strptime(locked_until, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                locked_until = None
        elif getattr(locked_until, "tzinfo", None) is None and locked_until is not None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until and locked_until > datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is locked",
            )
        raw_org = user.get("organization_id")
        raw_uid = user.get("id")
        raw_role = user.get("role")
        raw_uname = user.get("username")
        raw_email = user.get("email")
        return SecurityContext(
            user_id=str(raw_uid) if raw_uid is not None else None,
            organization_id=str(raw_org) if raw_org is not None else None,
            role=str(raw_role) if raw_role is not None else None,
            username=str(raw_uname) if raw_uname is not None else None,
            email=str(raw_email) if raw_email is not None else None,
        )
    except (JWTError, ValidationError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def require_org_scoped_role(*roles: str):
    """FastAPI dependency factory enforcing role requirements and providing organization context."""
    allowed_roles = set(roles) if roles else {"org_admin", "super_admin"}

    def dependency(user: dict = Depends(get_current_user)) -> dict:
        role = user.get("role")
        if role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return dependency


def require_super_admin(user: dict = Depends(get_current_user)):
    """Require super_admin role (Issue #3: Added admin authorization)"""
    if user.get("role") != 'super_admin':
        raise HTTPException(status_code=403, detail="Super Admin access required")
    return user

def require_org_admin(user: dict = Depends(get_current_user)):
    """Require org_admin or super_admin role (Issue #3: Added admin authorization)"""
    if user.get("role") not in ['super_admin', 'org_admin']:
        raise HTTPException(status_code=403, detail="Organization Admin access required")
    return user

def admin_required(user: dict = Depends(get_current_user)):
    """Alias for require_org_admin - used for sensitive operations (Issue #3)"""
    if user.get("role") not in ['super_admin', 'org_admin']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return user

# --- RATE LIMITER ---
_rate_limit_buckets: dict[str, deque[float]] = {}
_rate_limit_lock = threading.Lock()


def _default_rate_limit_identity(request: Request) -> str:
    from backend.utils.network import resolve_source_ip
    client_ip = resolve_source_ip(request)
    return f"{client_ip}:{request.url.path}"


def request_rate_limit(
    *,
    limit: int,
    window_seconds: float,
    bucket: str,
    key_builder=None,
):
    max_requests = max(int(limit or 1), 1)
    window = max(float(window_seconds or 1.0), 1.0)

    def dependency(request: Request):
        from backend.db.redis_client import get_redis_connection
        import redis

        identity_builder = key_builder or _default_rate_limit_identity
        identity = str(identity_builder(request) or "anonymous")
        storage_key = f"ratelimit:{bucket}:{identity}"

        # Try Redis first (Distributed Rate Limiting)
        try:
            r = get_redis_connection()
            now = time.time()
            cutoff = now - window

            # Atomic sliding window using Redis transaction pipeline
            pipe = r.pipeline()
            pipe.zremrangebyscore(storage_key, 0, cutoff)
            pipe.zcard(storage_key)
            pipe.zadd(storage_key, {str(now): now})
            pipe.expire(storage_key, int(window) + 1)
            _, current_count, _, _ = pipe.execute()

            if current_count >= max_requests:
                metrics_service.increment(
                    "rate_limit_rejections_total",
                    bucket=bucket,
                    path=request.url.path,
                )
                raise HTTPException(status_code=429, detail="Too many requests")

            return True

        except (redis.exceptions.RedisError, redis.exceptions.ConnectionError, OSError) as e:
            # Fall back to thread-safe in-memory rate limiting if Redis fails
            logger.warning("Redis rate limiter failed, falling back to in-memory: %s", e)
            now = time.monotonic()
            cutoff = now - window

            with _rate_limit_lock:
                request_times = _rate_limit_buckets.setdefault(storage_key, deque())
                while request_times and request_times[0] <= cutoff:
                    request_times.popleft()

                if len(request_times) >= max_requests:
                    metrics_service.increment(
                        "rate_limit_rejections_total",
                        bucket=bucket,
                        path=request.url.path,
                    )
                    raise HTTPException(status_code=429, detail="Too many requests")

                request_times.append(now)

                if len(_rate_limit_buckets) > 10000:
                    stale_keys = [
                        key
                        for key, timestamps in _rate_limit_buckets.items()
                        if not timestamps or timestamps[-1] <= cutoff
                    ]
                    for key in stale_keys:
                        _rate_limit_buckets.pop(key, None)

            metrics_service.set_gauge("rate_limit_active_buckets", len(_rate_limit_buckets))
            return True

    return dependency


def rate_limit(seconds_between: float = 0.1):
    limit = 1
    window = max(float(seconds_between or 0.1), 0.1)
    return request_rate_limit(limit=limit, window_seconds=window, bucket="compat_rate_limit")
