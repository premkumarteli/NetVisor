-- Idempotent index addition for missing startup indexes required by backend/db/session.py
-- idx_alerts_org_resolved_time_sev and idx_web_events_org_last_seen_id

-- 1. alerts: idx_alerts_org_resolved_time_sev
SET @exist_alerts_idx := (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'alerts'
      AND index_name = 'idx_alerts_org_resolved_time_sev'
);
SET @sql_alerts_idx := IF(
    @exist_alerts_idx = 0,
    'CREATE INDEX idx_alerts_org_resolved_time_sev ON alerts (organization_id, resolved, timestamp, severity)',
    'SELECT "Index idx_alerts_org_resolved_time_sev already exists on alerts"'
);
PREPARE stmt_alerts FROM @sql_alerts_idx;
EXECUTE stmt_alerts;
DEALLOCATE PREPARE stmt_alerts;

-- 2. web_events: idx_web_events_org_last_seen_id
SET @exist_web_events_idx := (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'web_events'
      AND index_name = 'idx_web_events_org_last_seen_id'
);
SET @sql_web_events_idx := IF(
    @exist_web_events_idx = 0,
    'CREATE INDEX idx_web_events_org_last_seen_id ON web_events (organization_id, last_seen, id)',
    'SELECT "Index idx_web_events_org_last_seen_id already exists on web_events"'
);
PREPARE stmt_web_events FROM @sql_web_events_idx;
EXECUTE stmt_web_events;
DEALLOCATE PREPARE stmt_web_events;
