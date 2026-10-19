-- req_id groups every report from one attack period.
-- Safe to run multiple times on existing databases.

SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'security_events' AND COLUMN_NAME = 'req_id'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE security_events ADD COLUMN req_id VARCHAR(128) NOT NULL DEFAULT '''' AFTER event_data, ADD KEY idx_security_events_req (req_id, created_at)',
  'SELECT ''security_events.req_id already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'l4_live_attack' AND COLUMN_NAME = 'req_id'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE l4_live_attack ADD COLUMN req_id VARCHAR(128) NOT NULL DEFAULT '''' AFTER attack_type, ADD KEY idx_l4_live_attack_req (req_id, created_at)',
  'SELECT ''l4_live_attack.req_id already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
