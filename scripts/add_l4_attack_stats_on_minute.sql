-- Speeds long-range Analytics DDoS / Detection series by indexing one Sparta
-- sample per minute (SECOND(bucket_ts)=0) instead of scanning every second.
SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'l4_attack_stats'
    AND COLUMN_NAME = 'on_minute'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE l4_attack_stats ADD COLUMN on_minute TINYINT(1) GENERATED ALWAYS AS (SECOND(bucket_ts) = 0) STORED, ADD KEY idx_l4_attack_on_minute (on_minute, bucket_ts)',
  'SELECT ''l4_attack_stats.on_minute already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
