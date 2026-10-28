-- Cache-hit page detail from Angelos POST /api/report_cache_hit (Athens content_type + miss URL stats).

CREATE TABLE IF NOT EXISTS `content_type_request_stats` (
  `server_id` bigint(20) NOT NULL,
  `site_id` bigint(20) NOT NULL DEFAULT 0,
  `bucket_ts` datetime NOT NULL,
  `content_type` varchar(32) NOT NULL,
  `request_count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `traffic_l7_tx` bigint(20) unsigned NOT NULL DEFAULT 0,
  `cached_request_count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `traffic_cached_tx` bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`, `content_type`),
  KEY `idx_bucket` (`bucket_ts`),
  KEY `idx_site_bucket` (`site_id`, `bucket_ts`),
  KEY `idx_server_bucket` (`server_id`, `bucket_ts`),
  CONSTRAINT `content_type_request_stats_server_fk`
    FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `cache_miss_url_stats` (
  `server_id` bigint(20) NOT NULL,
  `site_id` bigint(20) NOT NULL DEFAULT 0,
  `bucket_ts` datetime NOT NULL,
  `url_hash` binary(16) NOT NULL,
  `domain` varchar(255) NOT NULL DEFAULT '',
  `request_url` varchar(1024) NOT NULL,
  `miss_count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `request_count` bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`, `url_hash`),
  KEY `idx_bucket` (`bucket_ts`),
  KEY `idx_site_bucket` (`site_id`, `bucket_ts`),
  KEY `idx_server_bucket` (`server_id`, `bucket_ts`),
  CONSTRAINT `cache_miss_url_stats_server_fk`
    FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
