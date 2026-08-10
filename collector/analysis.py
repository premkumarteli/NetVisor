from packet_engine.classifier import *
import packet_engine.metadata as _metadata

def _extract_tls_sni(payload: bytes):
    return _metadata._extract_tls_sni(payload)

def _extract_http_host(payload: bytes):
    return _metadata._extract_http_host(payload)
