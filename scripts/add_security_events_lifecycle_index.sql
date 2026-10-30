-- Speeds Overview /dashboard/security-events period discovery, which filters on
-- event_data / command instead of scanning every report_block_ip row.
SET @idx_exists := (
  SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'security_events'
    AND INDEX_NAME = 'idx_security_events_lifecycle'
);
SET @sql := IF(
  @idx_exists = 0,
  'ALTER TABLE security_events ADD KEY idx_security_events_lifecycle (command, event_data, created_at)',
  'SELECT ''idx_security_events_lifecycle already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
