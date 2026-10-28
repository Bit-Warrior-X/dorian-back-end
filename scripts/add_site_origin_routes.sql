USE cdnproxy;

CREATE TABLE IF NOT EXISTS `site_origin_routes` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `site_id` bigint(20) NOT NULL,
  `scheme` enum('HTTP','HTTPS') NOT NULL,
  `description` varchar(255) NOT NULL DEFAULT '',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_site_origin_routes_site` (`site_id`),
  KEY `idx_site_origin_routes_site_scheme` (`site_id`,`scheme`),
  CONSTRAINT `site_origin_routes_site_fk` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `site_origin_route_ports` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `route_id` bigint(20) NOT NULL,
  `site_id` bigint(20) NOT NULL,
  `scheme` enum('HTTP','HTTPS') NOT NULL,
  `port` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_site_origin_route_ports_site_scheme_port` (`site_id`,`scheme`,`port`),
  UNIQUE KEY `uk_site_origin_route_ports_route_port` (`route_id`,`port`),
  KEY `idx_site_origin_route_ports_route` (`route_id`),
  CONSTRAINT `site_origin_route_ports_route_fk` FOREIGN KEY (`route_id`) REFERENCES `site_origin_routes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `site_origin_route_ports_site_fk` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `site_origin_route_upstreams` (
  `route_id` bigint(20) NOT NULL,
  `upstream_server_id` bigint(20) NOT NULL,
  PRIMARY KEY (`route_id`,`upstream_server_id`),
  KEY `idx_site_origin_route_upstreams_upstream` (`upstream_server_id`),
  CONSTRAINT `site_origin_route_upstreams_route_fk` FOREIGN KEY (`route_id`) REFERENCES `site_origin_routes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `site_origin_route_upstreams_upstream_fk` FOREIGN KEY (`upstream_server_id`) REFERENCES `upstream_servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Backfill: one default route per scheme that already has selected listeners,
-- attaching every current upstream so behavior stays "shared pool".
INSERT INTO `site_origin_routes` (`site_id`, `scheme`, `description`)
SELECT DISTINCT s.id, UPPER(lp.protocol), 'Migrated default route'
FROM `sites` s
INNER JOIN `site_listening_ports` slp ON slp.site_id = s.id
INNER JOIN `listening_ports` lp ON lp.id = slp.listening_port_id
WHERE NOT EXISTS (
  SELECT 1 FROM `site_origin_routes` r WHERE r.site_id = s.id AND r.scheme = UPPER(lp.protocol)
);

INSERT INTO `site_origin_route_ports` (`route_id`, `site_id`, `scheme`, `port`)
SELECT r.id, r.site_id, r.scheme, lp.port
FROM `site_origin_routes` r
INNER JOIN (
  SELECT DISTINCT slp.site_id, UPPER(lp.protocol) AS scheme, lp.port
  FROM `site_listening_ports` slp
  INNER JOIN `listening_ports` lp ON lp.id = slp.listening_port_id
) lp ON lp.site_id = r.site_id AND lp.scheme = r.scheme
WHERE NOT EXISTS (
  SELECT 1 FROM `site_origin_route_ports` p
  WHERE p.site_id = r.site_id AND p.scheme = r.scheme AND p.port = lp.port
);

INSERT INTO `site_origin_route_upstreams` (`route_id`, `upstream_server_id`)
SELECT r.id, u.id
FROM `site_origin_routes` r
INNER JOIN `upstream_servers` u ON u.site_id = r.site_id
WHERE NOT EXISTS (
  SELECT 1 FROM `site_origin_route_upstreams` ru
  WHERE ru.route_id = r.id AND ru.upstream_server_id = u.id
);

-- Sites with upstreams but no selected listeners yet: one HTTP route with all upstreams, no ports.
INSERT INTO `site_origin_routes` (`site_id`, `scheme`, `description`)
SELECT DISTINCT u.site_id, 'HTTP', 'Migrated default route'
FROM `upstream_servers` u
WHERE NOT EXISTS (
  SELECT 1 FROM `site_origin_routes` r WHERE r.site_id = u.site_id
);

INSERT INTO `site_origin_route_upstreams` (`route_id`, `upstream_server_id`)
SELECT r.id, u.id
FROM `site_origin_routes` r
INNER JOIN `upstream_servers` u ON u.site_id = r.site_id
WHERE NOT EXISTS (
  SELECT 1 FROM `site_origin_route_upstreams` ru
  WHERE ru.route_id = r.id AND ru.upstream_server_id = u.id
);
