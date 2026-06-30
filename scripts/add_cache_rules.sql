CREATE TABLE IF NOT EXISTS `cache_rules` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `rule_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `rule_type` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'file',
  `caching_time` int NOT NULL DEFAULT 3600,
  `url` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `file_types` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `priority` int NOT NULL DEFAULT 1000,
  `cache_slice` double NOT NULL DEFAULT 100,
  `without_parameter` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'yes',
  `cache_mode` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'origin',
  `status` enum('ENABLE','DISABLE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ENABLE',
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `cache_rules_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
