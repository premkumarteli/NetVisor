import contextvars

# Async/Thread-safe request-scoped context variables to trigger simulated chaos
active_chaos_db_down = contextvars.ContextVar("active_chaos_db_down", default=False)
active_chaos_db_latency = contextvars.ContextVar("active_chaos_db_latency", default=0.0)
active_chaos_disk_full = contextvars.ContextVar("active_chaos_disk_full", default=False)
active_chaos_slow_dns = contextvars.ContextVar("active_chaos_slow_dns", default=0.0)
