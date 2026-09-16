-- Athens cache counters on site_traffic_stats (OpenAPI L7Counters).
-- cache_hit_ratio = cache_hit_count / (cache_hit_count + cache_miss_count)
USE cdnproxy;

ALTER TABLE `site_traffic_stats`
  ADD COLUMN `cache_hit_count` bigint unsigned NOT NULL DEFAULT '0' AFTER `http3_count`,
  ADD COLUMN `cache_miss_count` bigint unsigned NOT NULL DEFAULT '0' AFTER `cache_hit_count`,
  ADD COLUMN `cache_bypass_count` bigint unsigned NOT NULL DEFAULT '0' AFTER `cache_miss_count`,
  ADD COLUMN `cache_hit_ratio` double NOT NULL DEFAULT '0' AFTER `cache_bypass_count`;
