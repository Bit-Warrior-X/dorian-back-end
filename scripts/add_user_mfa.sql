-- TOTP two-factor authentication for console users.
-- Safe to run multiple times on existing databases.

SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'totp_secret'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64) NULL DEFAULT NULL AFTER password',
  'SELECT ''totp_secret already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'totp_pending_secret'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE users ADD COLUMN totp_pending_secret VARCHAR(64) NULL DEFAULT NULL AFTER totp_secret',
  'SELECT ''totp_pending_secret already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'totp_enabled_at'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE users ADD COLUMN totp_enabled_at DATETIME NULL DEFAULT NULL AFTER totp_pending_secret',
  'SELECT ''totp_enabled_at already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'totp_last_step'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE users ADD COLUMN totp_last_step BIGINT NOT NULL DEFAULT 0 AFTER totp_enabled_at',
  'SELECT ''totp_last_step already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS `user_recovery_codes` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `code_hash` char(64) NOT NULL,
  `used_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_recovery_code` (`user_id`, `code_hash`),
  CONSTRAINT `fk_user_recovery_codes_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
