CREATE TABLE IF NOT EXISTS `compress_settings` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `css` tinyint(1) NOT NULL DEFAULT 1,
  `html` tinyint(1) NOT NULL DEFAULT 1,
  `js` tinyint(1) NOT NULL DEFAULT 1,
  `audio` tinyint(1) NOT NULL DEFAULT 0,
  `font` tinyint(1) NOT NULL DEFAULT 0,
  `applications` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `compress_settings_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
