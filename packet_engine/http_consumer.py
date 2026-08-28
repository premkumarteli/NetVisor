from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("netvisor.packet_engine.http_consumer")


@dataclass(slots=True)
class HttpTransaction:
    method: str
    host: str
    uri: str
    user_agent: Optional[str] = None
    status_code: Optional[int] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    confidence: float = 1.00


class HttpStreamConsumer:
    """
    Bidirectional HTTP Request & Response Stream Transaction Reconstructor.
    Parses request lines (GET, POST, etc.) and response status lines (HTTP/1.1 200 OK) header windows.
    """
    HTTP_METHODS = (b"GET", b"POST", b"PUT", b"PATCH", b"DELETE", b"HEAD", b"OPTIONS", b"CONNECT")

    def parse_stream_chunk(self, stream_bytes: bytes) -> HttpTransaction | None:
        if not stream_bytes or len(stream_bytes) < 10:
            return None

        # Check for HTTP Response Line (HTTP/1.0 or HTTP/1.1)
        is_response = stream_bytes.startswith(b"HTTP/1.")
        is_request = False

        if not is_response:
            first_space = stream_bytes.find(b" ")
            if first_space != -1 and stream_bytes[:first_space] in self.HTTP_METHODS:
                is_request = True

        if not is_request and not is_response:
            return None

        # Limit header window to first 4,096 bytes
        header_window = stream_bytes[:4096]
        header_end = header_window.find(b"\r\n\r\n")
        if header_end != -1:
            header_window = header_window[:header_end]

        try:
            header_text = header_window.decode("utf-8", errors="ignore")
        except Exception:
            return None

        lines = header_text.splitlines()
        if not lines:
            return None

        first_line = lines[0].strip()
        parts = first_line.split()
        if len(parts) < 2:
            return None

        method = "RESPONSE" if is_response else parts[0].upper()
        uri = "" if is_response else parts[1]
        host = ""
        user_agent = None
        server = None
        status_code = None
        content_type = None
        content_length = None

        if is_response and len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                pass

        for line in lines[1:]:
            if not line:
                break
            header_name, sep, header_val = line.partition(":")
            if not sep:
                continue
            key = header_name.strip().lower()
            val = header_val.strip()
            if key == "host":
                host = val.lower()
            elif key == "user-agent":
                user_agent = val
            elif key == "server":
                server = val
            elif key == "content-type":
                content_type = val
            elif key == "content-length":
                try:
                    content_length = int(val)
                except ValueError:
                    pass

        if not host and uri.startswith("http"):
            uri_match = re.match(r"https?://([^/]+)", uri)
            if uri_match:
                host = uri_match.group(1).lower()

        return HttpTransaction(
            method=method,
            host=host or "unknown",
            uri=uri,
            user_agent=user_agent,
            status_code=status_code,
            server=server,
            content_type=content_type,
            content_length=content_length,
            confidence=1.00,
        )
