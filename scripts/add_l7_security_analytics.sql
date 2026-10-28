-- Durable L7 block history (survives Temporary blocks TTL expiry)
-- and per-minute WAF rule attribution from Athens /block_reason_stats.

CREATE TABLE IF NOT EXISTS `l7_block_events` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `server_id` bigint(20) NOT NULL,
  `site_id` bigint(20) NOT NULL DEFAULT 0,
  `source_ip` varchar(64) NOT NULL,
  `request_url` varchar(2048) NOT NULL DEFAULT '',
  `url_hash` int(10) unsigned NOT NULL DEFAULT 0,
  `trigger_rule` varchar(128) NOT NULL DEFAULT '',
  `country` varchar(64) NOT NULL DEFAULT '',
  `city` varchar(128) NOT NULL DEFAULT '',
  `ttl_seconds` int(11) NOT NULL DEFAULT 0,
  `blocked_at` datetime NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_l7_block_dedupe` (`server_id`, `source_ip`, `url_hash`, `trigger_rule`, `blocked_at`),
  KEY `idx_l7_block_created` (`created_at`),
  KEY `idx_l7_block_server_created` (`server_id`, `created_at`),
  KEY `idx_l7_block_site_created` (`site_id`, `created_at`),
  KEY `idx_l7_block_ip_created` (`source_ip`, `created_at`),
  CONSTRAINT `l7_block_events_server_fk`
    FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `block_reason_stats` (
  `server_id` bigint(20) NOT NULL,
  `site_id` bigint(20) NOT NULL DEFAULT 0,
  `bucket_ts` datetime NOT NULL,
  `rule_type` varchar(64) NOT NULL,
  `rule_id` varchar(128) NOT NULL DEFAULT '',
  `request_count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `ip_count` bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`, `rule_type`, `rule_id`),
  KEY `idx_block_reason_bucket` (`bucket_ts`),
  KEY `idx_block_reason_site_bucket` (`site_id`, `bucket_ts`),
  KEY `idx_block_reason_rule_bucket` (`rule_type`, `bucket_ts`),
  CONSTRAINT `block_reason_stats_server_fk`
    FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
