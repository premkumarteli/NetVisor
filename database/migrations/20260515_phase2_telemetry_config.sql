CREATE TABLE IF NOT EXISTS agent_configs (
    agent_id VARCHAR(100) PRIMARY KEY,
    organization_id CHAR(36),
    capture_backend VARCHAR(50) DEFAULT 'auto',
    promiscuous_mode BOOLEAN DEFAULT TRUE,
    flow_flush_interval_seconds INT DEFAULT 60,
    max_buffer_mb INT DEFAULT 500,
    telemetry_enabled BOOLEAN DEFAULT TRUE,
    telemetry_interval_seconds INT DEFAULT 60,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS telemetry_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(100) NOT NULL,
    organization_id CHAR(36),
    log_level VARCHAR(20) DEFAULT 'INFO',
    category VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    metadata_json TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_telemetry_agent (agent_id, timestamp),
    INDEX idx_telemetry_org (organization_id, timestamp),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);
