from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Union
import warnings

from jose import jwt
from cryptography.hazmat.primitives import serialization
import bcrypt
import uuid

from .config import get_settings, set_settings, Settings


def _load_private_key(settings: Settings = None) -> bytes:
    """Load RSA private key from settings (inline PEM or file path)."""
    s = settings or get_settings()
    if s.JWT_PRIVATE_KEY:
        return s.JWT_PRIVATE_KEY.encode()
    if s.JWT_PRIVATE_KEY_PATH:
        key_path = Path(s.JWT_PRIVATE_KEY_PATH)
        if not key_path.is_file():
            raise RuntimeError(
                f"Configured NETVISOR_JWT_PRIVATE_KEY_PATH does not exist or is not a file: {s.JWT_PRIVATE_KEY_PATH}"
            )
        with open(key_path, "rb") as f:
            return f.read()
    raise RuntimeError("No JWT private key configured. Set NETVISOR_JWT_PRIVATE_KEY or NETVISOR_JWT_PRIVATE_KEY_PATH.")


def _load_public_key(settings: Settings = None) -> bytes:
    """Load RSA public key from settings (inline PEM or file path)."""
    s = settings or get_settings()
    if s.JWT_PUBLIC_KEY:
        return s.JWT_PUBLIC_KEY.encode()
    if s.JWT_PUBLIC_KEY_PATH:
        key_path = Path(s.JWT_PUBLIC_KEY_PATH)
        if not key_path.is_file():
            raise RuntimeError(
                f"Configured NETVISOR_JWT_PUBLIC_KEY_PATH does not exist or is not a file: {s.JWT_PUBLIC_KEY_PATH}"
            )
        with open(key_path, "rb") as f:
            return f.read()
    raise RuntimeError("No JWT public key configured. Set NETVISOR_JWT_PUBLIC_KEY or NETVISOR_JWT_PUBLIC_KEY_PATH.")



def _get_signing_key(settings: Settings = None) -> bytes:
    """Get the key for signing tokens (private key for RS256, secret for HS256)."""
    s = settings or get_settings()
    algorithm = s.JWT_ALGORITHM.upper()
    if algorithm == "RS256":
        return _load_private_key(s)
    elif algorithm == "HS256":
        if not s.SECRET_KEY:
            raise RuntimeError("HS256 requires NETVISOR_SECRET_KEY")
        return s.SECRET_KEY.encode()
    else:
        raise ValueError(f"Unsupported JWT algorithm: {algorithm}")


def _get_verification_key(settings: Settings = None) -> bytes:
    """Get the key for verifying tokens (public key for RS256, secret for HS256)."""
    s = settings or get_settings()
    algorithm = s.JWT_ALGORITHM.upper()
    if algorithm == "RS256":
        return _load_public_key(s)
    elif algorithm == "HS256":
        if not s.SECRET_KEY:
            raise RuntimeError("HS256 requires NETVISOR_SECRET_KEY")
        return s.SECRET_KEY.encode()
    else:
        raise ValueError(f"Unsupported JWT algorithm: {algorithm}")


def create_access_token(subject: Union[str, Any], expires_delta: timedelta = None, extra_claims: dict = None, settings: Settings = None) -> str:
    """Create a JWT access token using configured algorithm (RS256 recommended)."""
    s = settings or get_settings()
    algorithm = s.JWT_ALGORITHM.upper()
    
    if algorithm == "HS256":
        warnings.warn(
            "HS256 is deprecated for access tokens. Use RS256 with NETVISOR_JWT_PRIVATE_KEY/NETVISOR_JWT_PUBLIC_KEY.",
            DeprecationWarning,
            stacklevel=2,
        )
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=max(int(s.ACCESS_TOKEN_MINUTES or 30), 1))
    
    now = datetime.now(timezone.utc)
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "iss": "netvisor-backend",
        "aud": "netvisor-clients",
        "iat": now,
        "jti": str(uuid.uuid4())
    }
    if extra_claims:
        to_encode.update(extra_claims)
    
    signing_key = _get_signing_key(s)
    encoded_jwt = jwt.encode(to_encode, signing_key, algorithm=algorithm)
    return encoded_jwt


def verify_access_token(token: str, settings: Settings = None) -> dict:
    """Verify and decode a JWT access token."""
    s = settings or get_settings()
    algorithm = s.JWT_ALGORITHM.upper()
    verification_key = _get_verification_key(s)
    
    try:
        payload = jwt.decode(
            token,
            verification_key,
            algorithms=[algorithm],
            issuer="netvisor-backend",
            audience="netvisor-clients",
        )
        return payload
    except Exception as e:
        raise ValueError(f"Invalid token: {e}")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
