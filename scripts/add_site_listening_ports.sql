USE cdnproxy;

CREATE TABLE IF NOT EXISTS `site_listening_ports` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `site_id` bigint NOT NULL,
  `listening_port_id` bigint NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `site_listening_port_unique` (`site_id`, `listening_port_id`) USING BTREE,
  KEY `site_id` (`site_id`) USING BTREE,
  KEY `listening_port_id` (`listening_port_id`) USING BTREE,
  CONSTRAINT `site_listening_ports_site_fk` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `site_listening_ports_port_fk` FOREIGN KEY (`listening_port_id`) REFERENCES `listening_ports` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
