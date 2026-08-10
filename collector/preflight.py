from socket import gethostbyname
try:
    import requests
except Exception:
    requests = None

from packet_engine.diagnostics import (
    PreflightResult,
    preflight_exit_code,
    print_preflight_report,
    run_preflight,
    serialize_preflight_results,
)

__all__ = [
    "PreflightResult",
    "preflight_exit_code",
    "print_preflight_report",
    "run_preflight",
    "serialize_preflight_results",
    "gethostbyname",
    "requests",
]
