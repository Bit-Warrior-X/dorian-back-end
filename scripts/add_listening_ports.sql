CREATE TABLE IF NOT EXISTS `listening_ports` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `port` int NOT NULL,
  `protocol` enum('HTTP','HTTPS') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'HTTP',
  `description` varchar(500) NOT NULL DEFAULT '',
  `status` enum('ENABLE','DISABLE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ENABLE',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `listening_ports_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
