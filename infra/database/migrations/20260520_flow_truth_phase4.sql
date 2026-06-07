ALTER TABLE flow_logs
    ADD COLUMN flow_direction VARCHAR(20) NOT NULL DEFAULT 'unknown' AFTER network_scope;

ALTER TABLE flow_logs
    ADD COLUMN analysis_source VARCHAR(64) NOT NULL DEFAULT 'transport_fallback' AFTER agent_id;

ALTER TABLE flow_logs
    ADD COLUMN analysis_confidence FLOAT NOT NULL DEFAULT 0.0 AFTER analysis_source;

ALTER TABLE flow_logs
    ADD COLUMN analysis_signals_json TEXT NULL AFTER analysis_confidence;

ALTER TABLE flow_logs
    ADD COLUMN ingest_hash CHAR(40) NULL AFTER analysis_signals_json;

CREATE INDEX idx_flow_logs_direction_last_seen
    ON flow_logs (flow_direction, last_seen);

CREATE INDEX idx_flow_logs_confidence_last_seen
    ON flow_logs (analysis_confidence, last_seen);

CREATE UNIQUE INDEX uq_flow_logs_ingest_hash
    ON flow_logs (ingest_hash);
