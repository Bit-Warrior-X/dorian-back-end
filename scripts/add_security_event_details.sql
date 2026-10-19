-- Store the XDP report fields that describe a security event.
-- Safe to run multiple times on existing databases.

SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'security_events' AND COLUMN_NAME = 'command'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE security_events
     ADD COLUMN command VARCHAR(64) NOT NULL DEFAULT '''' AFTER description,
     ADD COLUMN source_ip VARCHAR(64) NOT NULL DEFAULT '''' AFTER command,
     ADD COLUMN ttl VARCHAR(32) NOT NULL DEFAULT '''' AFTER source_ip,
     ADD COLUMN attack_type VARCHAR(64) NOT NULL DEFAULT '''' AFTER ttl,
     ADD COLUMN event_data VARCHAR(255) NOT NULL DEFAULT '''' AFTER attack_type',
  'SELECT ''security event detail columns already exist'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
