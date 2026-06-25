ALTER TABLE audit_logs ADD COLUMN ip_address VARCHAR(45) NULL AFTER action;
ALTER TABLE audit_logs ADD COLUMN resource VARCHAR(100) NULL AFTER ip_address;
