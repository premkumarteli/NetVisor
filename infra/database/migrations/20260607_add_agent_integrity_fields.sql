-- Add agent integrity status and manifest hash columns to agents table
ALTER TABLE agents ADD COLUMN integrity_status VARCHAR(32) NOT NULL DEFAULT 'unknown' AFTER ram_usage;
ALTER TABLE agents ADD COLUMN manifest_hash CHAR(64) NULL AFTER integrity_status;
