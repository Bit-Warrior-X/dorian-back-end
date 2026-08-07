USE cdnproxy;

-- Add per-origin protocol on upstream servers.
SET @has_upstream_protocol := (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'upstream_servers'
    AND COLUMN_NAME = 'protocol'
);
SET @sql := IF(
  @has_upstream_protocol = 0,
  'ALTER TABLE upstream_servers ADD COLUMN protocol enum(''HTTP'',''HTTPS'') NOT NULL DEFAULT ''HTTP'' AFTER ip_port',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Backfill protocol from legacy description encoding when present.
UPDATE upstream_servers
SET protocol = 'HTTPS'
WHERE UPPER(description) LIKE '%PROTOCOL=HTTPS%';

-- Remove site-level protocol badges.
SET @has_site_protocol := (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'sites'
    AND COLUMN_NAME = 'protocol_badges'
);
SET @sql := IF(
  @has_site_protocol > 0,
  'ALTER TABLE sites DROP COLUMN protocol_badges',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
