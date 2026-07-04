-- Migration: Add tenant isolation to device_risks table
-- 1. Add organization_id column as nullable CHAR(36)
ALTER TABLE device_risks ADD COLUMN organization_id CHAR(36) NULL AFTER device_id;

-- 2. Backfill organization_id from devices table matching on IP (device_id is IP in current database)
-- For any risks not matched in devices, fall back to the first available organization or default-org-id
-- Uses MAX(organization_id) to avoid ONLY_FULL_GROUP_BY error in MySQL
UPDATE device_risks r
LEFT JOIN (
    SELECT ip, MAX(organization_id) AS organization_id
    FROM devices 
    WHERE organization_id IS NOT NULL 
    GROUP BY ip
) d ON r.device_id = d.ip
SET r.organization_id = COALESCE(d.organization_id, (SELECT id FROM organizations LIMIT 1), 'default-org-id');

-- 3. Modify organization_id to be NOT NULL
ALTER TABLE device_risks MODIFY COLUMN organization_id CHAR(36) NOT NULL;

-- 4. Recreate Primary Key as a composite of (organization_id, device_id)
ALTER TABLE device_risks DROP PRIMARY KEY, ADD PRIMARY KEY (organization_id, device_id);

-- 5. Add foreign key constraint to organizations table
ALTER TABLE device_risks ADD CONSTRAINT fk_device_risks_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;

-- 6. Add index for severity/risk level dashboard queries
ALTER TABLE device_risks ADD INDEX idx_org_risk_severity (organization_id, risk_level);
