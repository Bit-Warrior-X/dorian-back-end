-- Link security events to the edge that reported them so non-admin users only see
-- events for their own edges. Existing rows keep server_id NULL (admin-only).
-- Safe to run multiple times on existing databases.

SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'security_events' AND COLUMN_NAME = 'server_id'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE security_events ADD COLUMN server_id BIGINT NULL DEFAULT NULL AFTER id, ADD KEY idx_security_events_server_created (server_id, created_at)',
  'SELECT ''server_id already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
