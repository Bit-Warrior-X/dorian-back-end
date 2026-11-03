-- Speeds Analytics → DDoS (L4) attack summary / recent / top-IP queries that
-- filter l4_live_attack by created_at (previously a full table scan).
SET @idx_exists := (
  SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'l4_live_attack'
    AND INDEX_NAME = 'idx_l4_live_attack_created'
);
SET @sql := IF(
  @idx_exists = 0,
  'ALTER TABLE l4_live_attack ADD KEY idx_l4_live_attack_created (created_at)',
  'SELECT ''idx_l4_live_attack_created already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
