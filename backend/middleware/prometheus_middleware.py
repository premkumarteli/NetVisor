import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

# Metrics definitions
HTTP_REQUEST_COUNT = Counter(
    "netvisor_http_requests_total",
    "Total number of HTTP requests processed",
    ["method", "endpoint", "http_status"]
)

HTTP_REQUEST_LATENCY = Histogram(
    "netvisor_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"]
)

FLOWS_INGESTED_TOTAL = Counter(
    "netvisor_flows_ingested_total",
    "Total number of network flows ingested",
    ["client_id"]
)

INGESTION_QUEUE_LAG = Gauge(
    "netvisor_ingestion_queue_lag",
    "Current lag/depth in the flow ingestion queue"
)

DATABASE_OP_LATENCY = Histogram(
    "netvisor_database_op_duration_seconds",
    "Database operation latency in seconds",
    ["operation"]
)

SYSTEM_CPU_USAGE = Gauge("netvisor_system_cpu_usage", "System CPU usage percentage")
SYSTEM_RAM_USAGE = Gauge("netvisor_system_ram_usage_bytes", "System RAM usage in bytes")

# Business Metrics (Exit Criteria 7)
ALERTS_GENERATED = Counter(
    "netvisor_alerts_generated_total",
    "Total number of alerts generated",
    ["severity"]
)
INCIDENTS_CREATED = Counter(
    "netvisor_incidents_created_total",
    "Total number of consolidated incident graphs created"
)
DETECTIONS_PER_ENGINE = Counter(
    "netvisor_detections_per_engine_total",
    "Total detections generated per threat engine",
    ["engine"]
)
ENGINE_RUNTIME = Histogram(
    "netvisor_engine_runtime_seconds",
    "Execution runtime in seconds per threat engine",
    ["engine"]
)
QUEUE_DEPTH = Gauge(
    "netvisor_queue_depth",
    "Current number of pending flows or batches in the ingestion pipeline"
)

REDIS_STREAM_LENGTH = Gauge(
    "netvisor_redis_stream_length",
    "Current length of the Redis flow stream"
)
REDIS_CONSUMER_LAG = Gauge(
    "netvisor_redis_consumer_lag",
    "Current consumer lag in Redis Streams"
)
CLICKHOUSE_INSERT_LATENCY = Histogram(
    "netvisor_clickhouse_insert_duration_seconds",
    "ClickHouse bulk insertion latency in seconds"
)
CLICKHOUSE_INSERT_ROWS = Counter(
    "netvisor_clickhouse_inserted_rows_total",
    "Total number of rows successfully inserted to ClickHouse"
)

FLOWS_DROPPED = Counter(
    "netvisor_flows_dropped_total",
    "Total number of flows dropped due to queue backpressure or validation failures"
)
WORKER_RESTART_COUNT = Counter(
    "netvisor_worker_restarts_total",
    "Total number of background queue worker task restarts"
)

class PrometheusMiddleware(BaseHTTPMiddleware):
    """Middleware for gathering request performance and throughput metrics."""
    
    async def dispatch(self, request: Request, call_next):
        # Bypass metrics endpoint itself to avoid recursion/clutter
        if request.url.path == "/metrics":
            return await call_next(request)
            
        method = request.method
        path = request.url.path
        
        start_time = time.perf_counter()
        
        try:
            response = await call_next(request)
            status_code = str(response.status_code)
            return response
        except Exception as exc:
            status_code = "500"
            raise exc
        finally:
            latency = time.perf_counter() - start_time
            # Record metrics
            HTTP_REQUEST_COUNT.labels(method=method, endpoint=path, http_status=status_code).inc()
            HTTP_REQUEST_LATENCY.labels(method=method, endpoint=path).observe(latency)

def metrics_endpoint_handler(request: Request) -> Response:
    """Exposes Prometheus text-format metrics."""
    # Update system metrics before scraping
    try:
        import psutil
        SYSTEM_CPU_USAGE.set(psutil.cpu_percent())
        SYSTEM_RAM_USAGE.set(psutil.virtual_memory().used)
    except ImportError:
        pass # psutil not installed, skip CPU/RAM system metrics
        
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
