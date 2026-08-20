-- Site-scoped Athens metrics: add site_id to dimension tables and create site/domain traffic tables.
USE cdnproxy;

-- Dimension tables: add site_id and rebuild primary keys.
ALTER TABLE `ip_request_stats`
  ADD COLUMN `site_id` bigint NOT NULL DEFAULT 0 AFTER `server_id`,
  DROP PRIMARY KEY,
  ADD PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`, `ip`),
  ADD KEY `idx_site_bucket` (`site_id`, `bucket_ts`);

ALTER TABLE `isp_request_stats`
  ADD COLUMN `site_id` bigint NOT NULL DEFAULT 0 AFTER `server_id`,
  DROP PRIMARY KEY,
  ADD PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`, `isp_hash`),
  ADD KEY `idx_site_bucket` (`site_id`, `bucket_ts`);

ALTER TABLE `country_request_stats`
  ADD COLUMN `site_id` bigint NOT NULL DEFAULT 0 AFTER `server_id`,
  DROP PRIMARY KEY,
  ADD PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`, `country_code`),
  ADD KEY `idx_site_bucket` (`site_id`, `bucket_ts`);

ALTER TABLE `referer_request_stats`
  ADD COLUMN `site_id` bigint NOT NULL DEFAULT 0 AFTER `server_id`,
  DROP PRIMARY KEY,
  ADD PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`, `referer_hash`),
  ADD KEY `idx_site_bucket` (`site_id`, `bucket_ts`);

ALTER TABLE `url_request_stats`
  ADD COLUMN `site_id` bigint NOT NULL DEFAULT 0 AFTER `server_id`,
  DROP PRIMARY KEY,
  ADD PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`, `url_hash`),
  ADD KEY `idx_site_bucket` (`site_id`, `bucket_ts`);

ALTER TABLE `useragent_request_stats`
  ADD COLUMN `site_id` bigint NOT NULL DEFAULT 0 AFTER `server_id`,
  DROP PRIMARY KEY,
  ADD PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`, `useragent_hash`),
  ADD KEY `idx_site_bucket` (`site_id`, `bucket_ts`);

CREATE TABLE IF NOT EXISTS `site_traffic_stats` (
  `server_id` bigint NOT NULL,
  `site_id` bigint NOT NULL,
  `bucket_ts` datetime NOT NULL,
  `traffic_l7_rx` float unsigned NOT NULL DEFAULT (0),
  `traffic_l7_tx` float unsigned NOT NULL DEFAULT (0),
  `bandwidth_l7_rx` bigint unsigned NOT NULL DEFAULT '0',
  `bandwidth_l7_tx` bigint unsigned NOT NULL DEFAULT '0',
  `request_count` bigint unsigned NOT NULL DEFAULT '0',
  `response_count` bigint unsigned NOT NULL DEFAULT '0',
  `blocked_request_count` bigint unsigned NOT NULL DEFAULT '0',
  `ip_count` int unsigned NOT NULL DEFAULT '0',
  `blocked_ip_count` int unsigned NOT NULL DEFAULT '0',
  `code200` bigint unsigned NOT NULL DEFAULT '0',
  `code206` bigint unsigned NOT NULL DEFAULT '0',
  `code301` bigint unsigned NOT NULL DEFAULT '0',
  `code302` bigint unsigned NOT NULL DEFAULT '0',
  `code400` bigint unsigned NOT NULL DEFAULT '0',
  `code403` bigint unsigned NOT NULL DEFAULT '0',
  `code404` bigint unsigned NOT NULL DEFAULT '0',
  `code444` bigint unsigned NOT NULL DEFAULT '0',
  `code499` bigint unsigned NOT NULL DEFAULT '0',
  `code500` bigint unsigned NOT NULL DEFAULT '0',
  `code501` bigint unsigned NOT NULL DEFAULT '0',
  `code502` bigint unsigned NOT NULL DEFAULT '0',
  `code503` bigint unsigned NOT NULL DEFAULT '0',
  `code504` bigint unsigned NOT NULL DEFAULT '0',
  `code904` bigint unsigned NOT NULL DEFAULT '0',
  `code929` bigint unsigned NOT NULL DEFAULT '0',
  `code978` bigint unsigned NOT NULL DEFAULT '0',
  `get_count` bigint unsigned NOT NULL DEFAULT '0',
  `post_count` bigint unsigned NOT NULL DEFAULT '0',
  `delete_count` bigint unsigned NOT NULL DEFAULT '0',
  `put_count` bigint unsigned NOT NULL DEFAULT '0',
  `head_count` bigint unsigned NOT NULL DEFAULT '0',
  `patch_count` bigint unsigned NOT NULL DEFAULT '0',
  `options_count` bigint unsigned NOT NULL DEFAULT '0',
  `others_count` bigint unsigned NOT NULL DEFAULT '0',
  `http1_0_count` bigint unsigned NOT NULL DEFAULT '0',
  `http1_1_count` bigint unsigned NOT NULL DEFAULT '0',
  `http2_count` bigint unsigned NOT NULL DEFAULT '0',
  `http3_count` bigint unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`),
  KEY `idx_bucket` (`bucket_ts`),
  KEY `idx_site_bucket` (`site_id`, `bucket_ts`),
  KEY `idx_server_bucket` (`server_id`, `bucket_ts`),
  CONSTRAINT `site_traffic_stats_server_fk` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `domain_request_stats` (
  `server_id` bigint NOT NULL,
  `site_id` bigint NOT NULL,
  `bucket_ts` datetime NOT NULL,
  `domain_hash` binary(16) NOT NULL,
  `request_domain` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `request_count` int unsigned NOT NULL DEFAULT '1',
  `traffic_l7_rx` bigint unsigned NOT NULL DEFAULT '0',
  `traffic_l7_tx` bigint unsigned NOT NULL DEFAULT '0',
  `bandwidth_l7_rx` bigint unsigned NOT NULL DEFAULT '0',
  `bandwidth_l7_tx` bigint unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`server_id`, `site_id`, `bucket_ts`, `domain_hash`),
  KEY `idx_bucket` (`bucket_ts`),
  KEY `idx_site_bucket` (`site_id`, `bucket_ts`),
  KEY `idx_server_bucket` (`server_id`, `bucket_ts`),
  CONSTRAINT `domain_request_stats_server_fk` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
