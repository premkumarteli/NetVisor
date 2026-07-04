from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


import re

SENSITIVE_QUERY_KEYWORDS = ("token", "auth", "code", "session", "key", "password")
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}
MAX_SNIPPET_BYTES = 256

UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
JWT_PATTERN = re.compile(r"^eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*$")
HIGH_ENTROPY_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{32,}$|^[a-zA-Z0-9+/=]{32,}$")

SENSITIVE_PATH_KEYWORDS = {"reset-password", "verify", "magic", "invite", "oauth", "token", "reset", "session"}


def redact_headers(headers: dict | None) -> dict:
    redacted = {}
    for key, value in (headers or {}).items():
        normalized_key = str(key).strip()
        lower_key = normalized_key.lower()
        if lower_key in SENSITIVE_HEADERS or lower_key.startswith("x-auth-"):
            redacted[normalized_key] = "[REDACTED]"
        else:
            redacted[normalized_key] = value
    return redacted


def redact_url(url: str, *, keep_youtube_values: bool = True) -> str:
    if not url:
        return ""

    split = urlsplit(url)
    
    # 1. Redact query parameters
    query_pairs = []
    for key, value in parse_qsl(split.query, keep_blank_values=True):
        lower_key = key.lower()
        if "youtube.com" in split.netloc and keep_youtube_values and lower_key in {"v", "list", "t"}:
            query_pairs.append((key, value))
            continue
        if (
            any(token in lower_key for token in SENSITIVE_QUERY_KEYWORDS)
            or UUID_PATTERN.match(value)
            or JWT_PATTERN.match(value)
            or HIGH_ENTROPY_PATTERN.match(value)
        ):
            query_pairs.append((key, "[REDACTED]"))
        elif "youtube.com" in split.netloc:
            continue
        else:
            query_pairs.append((key, value))
    redacted_query = urlencode(query_pairs, doseq=True)
    
    # 2. Redact path segments
    path_segments = split.path.split("/")
    redacted_segments = []
    
    for i, segment in enumerate(path_segments):
        if not segment:
            redacted_segments.append(segment)
            continue
        
        is_secret = (
            UUID_PATTERN.match(segment)
            or JWT_PATTERN.match(segment)
            or HIGH_ENTROPY_PATTERN.match(segment)
        )
        
        prev_is_sensitive = False
        if i > 0:
            prev_segment = path_segments[i - 1].lower()
            if prev_segment in SENSITIVE_PATH_KEYWORDS:
                prev_is_sensitive = True
                
        if is_secret or prev_is_sensitive:
            redacted_segments.append("[REDACTED]")
        else:
            redacted_segments.append(segment)
            
    redacted_path = "/".join(redacted_segments)
    return urlunsplit((split.scheme, split.netloc, redacted_path, redacted_query, split.fragment))


def sanitize_text_snippet(value: str | bytes | None, *, max_bytes: int = MAX_SNIPPET_BYTES) -> str | None:
    if value in (None, "", b""):
        return None
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)

    text = text.replace("\x00", " ").strip()
    if not text:
        return None

    snippet = text.encode("utf-8", errors="replace")[: max(0, min(max_bytes, MAX_SNIPPET_BYTES))]
    return snippet.decode("utf-8", errors="replace").strip() or None


def hash_text(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
