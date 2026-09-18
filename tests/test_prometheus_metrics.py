"""Verify all prometheus_client Histogram/Counter/Gauge metrics can be observed without ValueError.

Catches the root cause of the DATABASE_OP_LATENCY bug: a metric defined with labels
but called without .labels(...).observe(...)."""
import pytest


def test_database_op_latency_bare_observe():
    from backend.middleware.prometheus_middleware import DATABASE_OP_LATENCY
    DATABASE_OP_LATENCY.observe(0.01)


def test_detection_latency_bare_observe():
    from backend.middleware.prometheus_middleware import DETECTION_LATENCY
    DETECTION_LATENCY.observe(0.01)


def test_alert_write_latency_bare_observe():
    from backend.middleware.prometheus_middleware import ALERT_WRITE_LATENCY
    ALERT_WRITE_LATENCY.observe(0.01)


def test_clickhouse_insert_latency_bare_observe():
    from backend.middleware.prometheus_middleware import CLICKHOUSE_INSERT_LATENCY
    CLICKHOUSE_INSERT_LATENCY.observe(0.01)


def test_engine_runtime_requires_labels():
    from backend.middleware.prometheus_middleware import ENGINE_RUNTIME
    with pytest.raises(ValueError, match="missing label values"):
        ENGINE_RUNTIME.observe(0.001)


def test_http_request_latency_requires_labels():
    from backend.middleware.prometheus_middleware import HTTP_REQUEST_LATENCY
    with pytest.raises(ValueError, match="missing label values"):
        HTTP_REQUEST_LATENCY.observe(0.001)


def test_counters_and_gauges_observable():
    from backend.middleware.prometheus_middleware import (
        FLOWS_DROPPED, QUEUE_OVERFLOW_TOTAL,
        INGESTION_QUEUE_LAG, QUEUE_DEPTH,
    )
    FLOWS_DROPPED.inc()
    QUEUE_OVERFLOW_TOTAL.inc()
    INGESTION_QUEUE_LAG.set(5)
    QUEUE_DEPTH.set(10)
