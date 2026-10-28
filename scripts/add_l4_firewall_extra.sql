-- Adaptive L4 / Sparta keys live beside classic columns as JSON.
-- Safe to run multiple times.

SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'l4_ddos_defense'
    AND COLUMN_NAME = 'firewall_extra'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE l4_ddos_defense ADD COLUMN firewall_extra LONGTEXT NULL AFTER tcp_connection_limit_cnt',
  'SELECT ''l4_ddos_defense.firewall_extra already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
