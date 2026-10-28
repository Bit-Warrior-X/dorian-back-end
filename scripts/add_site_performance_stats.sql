-- Per-site performance counters from Athens site_traffic_stats (latency hist + origin status).

CREATE TABLE IF NOT EXISTS `site_performance_stats` (
  `server_id` bigint(20) NOT NULL,
  `site_id` bigint(20) NOT NULL DEFAULT 0,
  `bucket_ts` datetime NOT NULL,
  `request_count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `origin_request_count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `origin_code2xx` bigint(20) unsigned NOT NULL DEFAULT 0,
  `origin_code3xx` bigint(20) unsigned NOT NULL DEFAULT 0,
  `origin_code4xx` bigint(20) unsigned NOT NULL DEFAULT 0,
  `origin_code5xx` bigint(20) unsigned NOT NULL DEFAULT 0,
  `origin_timeout_count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `origin_error_count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `edge_latency_hist` json NOT NULL,
  `edge_latency_sum_ms` double NOT NULL DEFAULT 0,
  `origin_latency_hist` json NOT NULL,
  `origin_latency_sum_ms` double NOT NULL DEFAULT 0,
  PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`),
  KEY `idx_bucket` (`bucket_ts`),
  KEY `idx_site_bucket` (`site_id`, `bucket_ts`),
  KEY `idx_server_bucket` (`server_id`, `bucket_ts`),
  CONSTRAINT `site_performance_stats_server_fk`
    FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
