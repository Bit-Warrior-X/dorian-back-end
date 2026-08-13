USE cdnproxy;

ALTER TABLE `blacklist`
  ADD COLUMN `site_id` bigint DEFAULT NULL AFTER `server_id`,
  ADD KEY `site_id` (`site_id`) USING BTREE,
  ADD CONSTRAINT `blacklist_site_fk` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;
