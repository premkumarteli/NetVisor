from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .http_consumer import HttpStreamConsumer
from .tls_consumer import TlsStreamConsumer

logger = logging.getLogger("netvisor.packet_engine.stream_registry")

CONFIDENCE_MATRIX = {
    "VERIFIED_L7_HEADER": 1.00,      # Parsed TLS ClientHello, HTTP Request, QUIC Initial, DNS Header
    "PORT_AND_SIGNATURE_MATCH": 0.90,# Signature matches expected port
    "PORT_MAPPING_ONLY": 0.60,       # Port mapping fallback without payload validation
    "STATISTICAL_HEURISTIC": 0.40,   # Statistical pattern heuristic
}


class StreamConsumerRegistry:
    """
    Decoupled Application Stream Consumers Registry.
    Routes reassembled TCP/UDP stream payloads to protocol-specific consumers (HTTP, TLS, SMB, QUIC).
    """

    def __init__(self) -> None:
        self._consumers: Dict[str, Any] = {
            "HTTP": HttpStreamConsumer(),
            "HTTPS": TlsStreamConsumer(),
            "TLS": TlsStreamConsumer(),
        }

    def register_consumer(self, protocol_name: str, consumer_instance: Any) -> None:
        key = str(protocol_name or "").strip().upper()
        if key:
            self._consumers[key] = consumer_instance

    def process_stream(self, protocol_name: str, stream_bytes: bytes) -> Optional[Any]:
        key = str(protocol_name or "").strip().upper()
        consumer = self._consumers.get(key)
        if consumer is None:
            # Fallback check for HTTP or TLS signatures if protocol is generic TCP
            if key in ("TCP", "UNKNOWN"):
                if stream_bytes and len(stream_bytes) > 5 and stream_bytes[0] == 0x16:
                    consumer = self._consumers.get("TLS")
                elif stream_bytes and stream_bytes.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ")):
                    consumer = self._consumers.get("HTTP")

        if consumer and hasattr(consumer, "parse_stream_chunk"):
            try:
                return consumer.parse_stream_chunk(stream_bytes)
            except Exception as exc:
                logger.debug("Stream consumer %s execution failed: %s", key, exc)

        return None
