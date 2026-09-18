-- Migration: Add hybrid device identity (Option 2)
-- 1. Add device_uuid column to devices table
ALTER TABLE devices ADD COLUMN device_uuid CHAR(36) NULL AFTER agent_id;

-- 2. Add composite unique index uq_device_uuid_org on (device_uuid, organization_id)
ALTER TABLE devices ADD UNIQUE KEY uq_device_uuid_org (device_uuid, organization_id);

-- 3. Create device_mac_addresses table for multi-NIC interface mapping and active staleness pruning
CREATE TABLE IF NOT EXISTS device_mac_addresses (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    device_uuid CHAR(36) NOT NULL,
    mac VARCHAR(20) NOT NULL,
    organization_id CHAR(36) NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    consecutive_misses INT NOT NULL DEFAULT 0,
    UNIQUE KEY uq_device_mac_org (mac, organization_id),
    INDEX idx_dma_lookup (organization_id, mac, last_seen),
    INDEX idx_dma_uuid (device_uuid, organization_id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Create device_identity_conflicts table for tracking UUID conflicts and re-provisioning events
CREATE TABLE IF NOT EXISTS device_identity_conflicts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    organization_id CHAR(36) NULL,
    existing_device_uuid CHAR(36) NOT NULL,
    incoming_device_uuid CHAR(36) NOT NULL,
    conflict_mac VARCHAR(20) NOT NULL,
    consecutive_heartbeats INT NOT NULL DEFAULT 1,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    UNIQUE KEY uq_conflict_pair (organization_id, existing_device_uuid, incoming_device_uuid, conflict_mac),
    INDEX idx_conflict_lookup (organization_id, incoming_device_uuid, status),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
