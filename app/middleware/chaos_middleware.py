import time
import shutil
import socket
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import logging

from .chaos_context import (
    active_chaos_db_down,
    active_chaos_db_latency,
    active_chaos_disk_full,
    active_chaos_slow_dns
)

logger = logging.getLogger("netvisor.chaos")

# Intercept global shutil.disk_usage and socket.getaddrinfo once at import time
_original_disk_usage = shutil.disk_usage
_original_getaddrinfo = socket.getaddrinfo

# Wrapper for disk_usage checks that looks at contextvars
def chaos_disk_usage(path):
    if active_chaos_disk_full.get():
        logger.warning("Chaos: Simulating Disk Full (96%) via ContextVar")
        # 100GB total, 96GB used (96% full)
        return shutil._ntuple_diskusage(100*1024*1024*1024, 96*1024*1024*1024, 4*1024*1024*1024)
    return _original_disk_usage(path)

# Wrapper for getaddrinfo lookups that looks at contextvars
def chaos_getaddrinfo(*args, **kwargs):
    dns_sec = active_chaos_slow_dns.get()
    if dns_sec > 0:
        logger.warning(f"Chaos: Injecting {dns_sec}s DNS latency via ContextVar")
        time.sleep(dns_sec)
    return _original_getaddrinfo(*args, **kwargs)

# Hook wrappers globally at server launch
shutil.disk_usage = chaos_disk_usage
socket.getaddrinfo = chaos_getaddrinfo

class ChaosMiddleware(BaseHTTPMiddleware):
    """Middleware that populates request-scoped context variables to trigger thread-safe chaos."""
    
    async def dispatch(self, request: Request, call_next):
        # 1. Parse chaos headers
        db_down = request.headers.get("X-Chaos-DB-Down") == "1"
        db_latency = request.headers.get("X-Chaos-DB-Latency")
        disk_full = request.headers.get("X-Chaos-Disk-Full") == "1"
        slow_dns = request.headers.get("X-Chaos-Slow-DNS")
        
        # 2. Set request-scoped context variables
        token_db_down = active_chaos_db_down.set(db_down)
        
        try:
            latency_sec = float(db_latency) if db_latency else 0.0
        except ValueError:
            latency_sec = 0.0
        token_db_latency = active_chaos_db_latency.set(latency_sec)
        
        token_disk_full = active_chaos_disk_full.set(disk_full)
        
        try:
            dns_sec = float(slow_dns) if slow_dns else 0.0
        except ValueError:
            dns_sec = 0.0
        token_slow_dns = active_chaos_slow_dns.set(dns_sec)
        
        try:
            response = await call_next(request)
            return response
        finally:
            # 3. Clean up/Reset context variables thread-safely
            active_chaos_db_down.reset(token_db_down)
            active_chaos_db_latency.reset(token_db_latency)
            active_chaos_disk_full.reset(token_disk_full)
            active_chaos_slow_dns.reset(token_slow_dns)
