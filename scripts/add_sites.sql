USE cdnproxy;

CREATE TABLE IF NOT EXISTS `sites` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `domain` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `status` enum('ENABLE','DISABLE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ENABLE',
  `waf_id` bigint DEFAULT NULL,
  `certificate_status` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'none',
  `certificate_expiry` datetime DEFAULT NULL,
  `cache_ratio` double NOT NULL DEFAULT 0,
  `bandwidth` bigint unsigned NOT NULL DEFAULT 0,
  `ssl_type` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'none',
  `ssl_cert` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `ssl_cert_key` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `unique_site_domain` (`domain`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `site_servers` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `site_id` bigint NOT NULL,
  `server_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_site_server` (`site_id`, `server_id`),
  KEY `server_id` (`server_id`),
  CONSTRAINT `site_servers_ibfk_1` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `site_servers_ibfk_2` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
