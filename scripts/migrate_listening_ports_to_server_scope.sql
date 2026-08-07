USE cdnproxy;

-- Move listening_ports from site scope back to server scope.

SET @has_server_id := (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'listening_ports'
    AND COLUMN_NAME = 'server_id'
);
SET @sql := IF(
  @has_server_id = 0,
  'ALTER TABLE listening_ports ADD COLUMN server_id bigint NULL AFTER id',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Allow temporary inserts without site_id while duplicating onto servers.
SET @has_site_id := (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'listening_ports'
    AND COLUMN_NAME = 'site_id'
);
SET @sql := IF(
  @has_site_id > 0,
  'ALTER TABLE listening_ports MODIFY site_id bigint NULL',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Duplicate each site listening port onto every assigned edge server.
SET @sql := IF(
  @has_site_id > 0,
  'INSERT INTO listening_ports (server_id, port, protocol, description, status, created_at, updated_at)
   SELECT ss.server_id, lp.port, lp.protocol, lp.description, lp.status, lp.created_at, lp.updated_at
   FROM listening_ports lp
   INNER JOIN site_servers ss ON ss.site_id = lp.site_id
   WHERE lp.site_id IS NOT NULL
     AND lp.server_id IS NULL
     AND NOT EXISTS (
       SELECT 1
       FROM listening_ports existing
       WHERE existing.server_id = ss.server_id
         AND existing.port = lp.port
     )',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Drop rows that remain site-scoped only.
DELETE FROM listening_ports WHERE server_id IS NULL;

-- Remove site FK/column and enforce server FK.
SET @has_site_fk := (
  SELECT COUNT(*)
  FROM information_schema.TABLE_CONSTRAINTS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'listening_ports'
    AND CONSTRAINT_NAME = 'listening_ports_site_fk'
);
SET @sql := IF(
  @has_site_fk > 0,
  'ALTER TABLE listening_ports DROP FOREIGN KEY listening_ports_site_fk',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @has_site_id := (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'listening_ports'
    AND COLUMN_NAME = 'site_id'
);
SET @sql := IF(
  @has_site_id > 0,
  'ALTER TABLE listening_ports DROP COLUMN site_id',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

DELETE FROM listening_ports WHERE server_id IS NULL;
ALTER TABLE listening_ports MODIFY server_id bigint NOT NULL;

SET @has_server_key := (
  SELECT COUNT(*)
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'listening_ports'
    AND INDEX_NAME = 'server_id'
);
SET @sql := IF(
  @has_server_key = 0,
  'ALTER TABLE listening_ports ADD KEY server_id (server_id)',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @has_server_fk := (
  SELECT COUNT(*)
  FROM information_schema.TABLE_CONSTRAINTS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'listening_ports'
    AND CONSTRAINT_NAME = 'listening_ports_server_fk'
);
SET @sql := IF(
  @has_server_fk = 0,
  'ALTER TABLE listening_ports ADD CONSTRAINT listening_ports_server_fk FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE ON UPDATE CASCADE',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
