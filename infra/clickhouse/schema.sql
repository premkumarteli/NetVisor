-- ===========================================================================
-- NetVisor Hyperscale ClickHouse Columnar Schema
-- Version: 2.0.0-HYPERSCALE
-- Features: DoubleDelta & T64 Codecs, LowCardinality Strings, 90-Day TTL,
--           5-Minute SummingMergeTree Pre-Aggregations
-- ===========================================================================

-- 1. Primary Flow Logs Telemetry Table (Optimized Columnar Storage)
CREATE TABLE IF NOT EXISTS flow_logs (
    organization_id LowCardinality(String),
    src_ip String,
    dst_ip String,
    src_port UInt32,
    dst_port UInt32,
    protocol LowCardinality(String),
    start_time DateTime CODEC(DoubleDelta, ZSTD(1)),
    last_seen DateTime CODEC(DoubleDelta, ZSTD(1)),
    packet_count UInt32 CODEC(T64, ZSTD(1)),
    byte_count UInt64 CODEC(T64, ZSTD(1)),
    duration Float32 CODEC(T64, ZSTD(1)),
    average_packet_size Float32 CODEC(T64, ZSTD(1)),
    domain LowCardinality(String),
    sni LowCardinality(String),
    src_mac String,
    dst_mac String,
    network_scope LowCardinality(String),
    flow_direction LowCardinality(String),
    internal_device_ip String,
    external_endpoint_ip String,
    session_id String,
    application LowCardinality(String),
    agent_id LowCardinality(String),
    analysis_source LowCardinality(String),
    analysis_confidence Float32 CODEC(T64, ZSTD(1)),
    analysis_signals_json String,
    ingest_hash String,
    created_at DateTime DEFAULT now() CODEC(DoubleDelta, ZSTD(1))
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(last_seen)
ORDER BY (organization_id, last_seen, src_ip, dst_port)
TTL last_seen + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- 2. Pre-Aggregated 5-Minute Analytical Rollup Table
CREATE TABLE IF NOT EXISTS flow_analytics_5m (
    window_start DateTime CODEC(DoubleDelta, ZSTD(1)),
    organization_id LowCardinality(String),
    application LowCardinality(String),
    internal_device_ip String,
    flow_count UInt64 CODEC(T64, ZSTD(1)),
    total_bytes UInt64 CODEC(T64, ZSTD(1)),
    total_packets UInt64 CODEC(T64, ZSTD(1)),
    max_duration Float32
) ENGINE = SummingMergeTree((flow_count, total_bytes, total_packets))
PARTITION BY toYYYYMM(window_start)
ORDER BY (organization_id, application, internal_device_ip, window_start)
TTL window_start + INTERVAL 365 DAY DELETE;

-- 3. Materialized View for Zero-Overhead Background Aggregation
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_flow_analytics_5m
TO flow_analytics_5m AS
SELECT
    toStartOfInterval(last_seen, INTERVAL 5 MINUTE) AS window_start,
    organization_id,
    application,
    internal_device_ip,
    count() AS flow_count,
    sum(byte_count) AS total_bytes,
    sum(packet_count) AS total_packets,
    max(duration) AS max_duration
FROM flow_logs
GROUP BY window_start, organization_id, application, internal_device_ip;
