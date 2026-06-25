-- mTLS certificate tracking fields for agents
-- Applied by: apply_20260607_add_mtls_fields.py

-- Agent certificate tracking columns
ALTER TABLE agents
  ADD COLUMN cert_serial VARCHAR(64) NULL,
  ADD COLUMN cert_fingerprint CHAR(64) NULL,
  ADD COLUMN cert_issued_at DATETIME NULL,
  ADD COLUMN cert_expires_at DATETIME NULL,
  ADD COLUMN cert_status VARCHAR(20) DEFAULT 'none';

-- Gateway certificate tracking columns
ALTER TABLE gateways
  ADD COLUMN cert_serial VARCHAR(64) NULL,
  ADD COLUMN cert_fingerprint CHAR(64) NULL,
  ADD COLUMN cert_issued_at DATETIME NULL,
  ADD COLUMN cert_expires_at DATETIME NULL,
  ADD COLUMN cert_status VARCHAR(20) DEFAULT 'none';

-- Certificate revocation log
CREATE TABLE IF NOT EXISTS certificate_revocations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  serial_number VARCHAR(64) NOT NULL,
  agent_id VARCHAR(100) NULL,
  revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  revoked_by VARCHAR(100) NULL,
  reason VARCHAR(255) NULL,
  UNIQUE KEY uq_cert_revocation_serial (serial_number),
  INDEX idx_cert_revocation_agent (agent_id)
);
