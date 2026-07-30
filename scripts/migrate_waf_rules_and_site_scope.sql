-- Idempotent migration: WAF rules scoped by waf_rule_id, traffic scoped by site_id.
-- Safe to re-run. Skips steps that were already applied.

USE cdnproxy;

DROP PROCEDURE IF EXISTS migrate_waf_rules_and_site_scope;
DELIMITER //
CREATE PROCEDURE migrate_waf_rules_and_site_scope()
BEGIN
  DECLARE waf_needs_migration INT DEFAULT 0;
  DECLARE traffic_needs_migration INT DEFAULT 0;
  DECLARE sites_fk_exists INT DEFAULT 0;

  -- waf_rule table (sites.waf_id references this)
  CREATE TABLE IF NOT EXISTS `waf_rule` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    `role` enum('predefined','custom') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

  SELECT COUNT(*) INTO waf_needs_migration
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'waf_whitelist'
    AND COLUMN_NAME = 'server_id';

  SELECT COUNT(*) INTO traffic_needs_migration
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'listening_ports'
    AND COLUMN_NAME = 'server_id';

  IF waf_needs_migration > 0 THEN
    -- Bootstrap waf_rule rows from existing server-scoped WAF data
    INSERT INTO waf_rule (`name`, `role`)
    SELECT DISTINCT CONCAT('Server #', s.id, ' WAF'), 'custom'
    FROM servers s
    WHERE EXISTS (
      SELECT 1 FROM waf_whitelist w WHERE w.server_id = s.id
    ) OR EXISTS (
      SELECT 1 FROM waf_blacklist w WHERE w.server_id = s.id
    ) OR EXISTS (
      SELECT 1 FROM waf_geolocation w WHERE w.server_id = s.id
    ) OR EXISTS (
      SELECT 1 FROM waf_anticc w WHERE w.server_id = s.id
    ) OR EXISTS (
      SELECT 1 FROM waf_antiheader w WHERE w.server_id = s.id
    ) OR EXISTS (
      SELECT 1 FROM waf_intervalfreqlimit w WHERE w.server_id = s.id
    ) OR EXISTS (
      SELECT 1 FROM waf_secondfreqlimit w WHERE w.server_id = s.id
    ) OR EXISTS (
      SELECT 1 FROM waf_responsefreq w WHERE w.server_id = s.id
    ) OR EXISTS (
      SELECT 1 FROM waf_useragent w WHERE w.server_id = s.id
    );

    DROP TEMPORARY TABLE IF EXISTS tmp_server_waf_rule;
    CREATE TEMPORARY TABLE tmp_server_waf_rule (
      server_id bigint NOT NULL PRIMARY KEY,
      waf_rule_id bigint NOT NULL
    );

    INSERT INTO tmp_server_waf_rule (server_id, waf_rule_id)
    SELECT s.id, wr.id
    FROM servers s
    JOIN waf_rule wr ON wr.name = CONCAT('Server #', s.id, ' WAF');

    -- waf_* tables: server_id -> waf_rule_id
    ALTER TABLE waf_whitelist ADD COLUMN waf_rule_id bigint NULL AFTER id;
    UPDATE waf_whitelist w JOIN tmp_server_waf_rule m ON w.server_id = m.server_id SET w.waf_rule_id = m.waf_rule_id;
    ALTER TABLE waf_whitelist DROP FOREIGN KEY waf_whitelist_ibfk_1;
    ALTER TABLE waf_whitelist DROP COLUMN server_id;
    ALTER TABLE waf_whitelist MODIFY waf_rule_id bigint NOT NULL;
    ALTER TABLE waf_whitelist ADD KEY waf_rule_id (waf_rule_id);
    ALTER TABLE waf_whitelist ADD CONSTRAINT waf_whitelist_waf_rule_fk FOREIGN KEY (waf_rule_id) REFERENCES waf_rule (id) ON DELETE CASCADE ON UPDATE CASCADE;

    ALTER TABLE waf_blacklist ADD COLUMN waf_rule_id bigint NULL AFTER id;
    UPDATE waf_blacklist w JOIN tmp_server_waf_rule m ON w.server_id = m.server_id SET w.waf_rule_id = m.waf_rule_id;
    ALTER TABLE waf_blacklist DROP FOREIGN KEY waf_blacklist_ibfk_1;
    ALTER TABLE waf_blacklist DROP COLUMN server_id;
    ALTER TABLE waf_blacklist MODIFY waf_rule_id bigint NOT NULL;
    ALTER TABLE waf_blacklist ADD KEY waf_rule_id (waf_rule_id);
    ALTER TABLE waf_blacklist ADD CONSTRAINT waf_blacklist_waf_rule_fk FOREIGN KEY (waf_rule_id) REFERENCES waf_rule (id) ON DELETE CASCADE ON UPDATE CASCADE;

    ALTER TABLE waf_geolocation ADD COLUMN waf_rule_id bigint NULL AFTER id;
    UPDATE waf_geolocation w JOIN tmp_server_waf_rule m ON w.server_id = m.server_id SET w.waf_rule_id = m.waf_rule_id;
    ALTER TABLE waf_geolocation DROP FOREIGN KEY waf_geolocation_ibfk_1;
    ALTER TABLE waf_geolocation DROP COLUMN server_id;
    ALTER TABLE waf_geolocation MODIFY waf_rule_id bigint NOT NULL;
    ALTER TABLE waf_geolocation ADD KEY waf_rule_id (waf_rule_id);
    ALTER TABLE waf_geolocation ADD CONSTRAINT waf_geolocation_waf_rule_fk FOREIGN KEY (waf_rule_id) REFERENCES waf_rule (id) ON DELETE CASCADE ON UPDATE CASCADE;

    ALTER TABLE waf_anticc ADD COLUMN waf_rule_id bigint NULL AFTER id;
    UPDATE waf_anticc w JOIN tmp_server_waf_rule m ON w.server_id = m.server_id SET w.waf_rule_id = m.waf_rule_id;
    ALTER TABLE waf_anticc DROP FOREIGN KEY waf_anticc_ibfk_1;
    ALTER TABLE waf_anticc DROP COLUMN server_id;
    ALTER TABLE waf_anticc MODIFY waf_rule_id bigint NOT NULL;
    ALTER TABLE waf_anticc ADD KEY waf_rule_id (waf_rule_id);
    ALTER TABLE waf_anticc ADD CONSTRAINT waf_anticc_waf_rule_fk FOREIGN KEY (waf_rule_id) REFERENCES waf_rule (id) ON DELETE CASCADE ON UPDATE CASCADE;

    ALTER TABLE waf_antiheader ADD COLUMN waf_rule_id bigint NULL AFTER id;
    UPDATE waf_antiheader w JOIN tmp_server_waf_rule m ON w.server_id = m.server_id SET w.waf_rule_id = m.waf_rule_id;
    ALTER TABLE waf_antiheader DROP FOREIGN KEY waf_antiheader_ibfk_1;
    ALTER TABLE waf_antiheader DROP COLUMN server_id;
    ALTER TABLE waf_antiheader MODIFY waf_rule_id bigint NOT NULL;
    ALTER TABLE waf_antiheader ADD KEY waf_rule_id (waf_rule_id);
    ALTER TABLE waf_antiheader ADD CONSTRAINT waf_antiheader_waf_rule_fk FOREIGN KEY (waf_rule_id) REFERENCES waf_rule (id) ON DELETE CASCADE ON UPDATE CASCADE;

    ALTER TABLE waf_intervalfreqlimit ADD COLUMN waf_rule_id bigint NULL AFTER id;
    UPDATE waf_intervalfreqlimit w JOIN tmp_server_waf_rule m ON w.server_id = m.server_id SET w.waf_rule_id = m.waf_rule_id;
    ALTER TABLE waf_intervalfreqlimit DROP FOREIGN KEY waf_intervalfreqlimit_ibfk_1;
    ALTER TABLE waf_intervalfreqlimit DROP COLUMN server_id;
    ALTER TABLE waf_intervalfreqlimit MODIFY waf_rule_id bigint NOT NULL;
    ALTER TABLE waf_intervalfreqlimit ADD KEY waf_rule_id (waf_rule_id);
    ALTER TABLE waf_intervalfreqlimit ADD CONSTRAINT waf_intervalfreqlimit_waf_rule_fk FOREIGN KEY (waf_rule_id) REFERENCES waf_rule (id) ON DELETE CASCADE ON UPDATE CASCADE;

    ALTER TABLE waf_secondfreqlimit ADD COLUMN waf_rule_id bigint NULL AFTER id;
    UPDATE waf_secondfreqlimit w JOIN tmp_server_waf_rule m ON w.server_id = m.server_id SET w.waf_rule_id = m.waf_rule_id;
    ALTER TABLE waf_secondfreqlimit DROP FOREIGN KEY waf_secondfreqlimit_ibfk_1;
    ALTER TABLE waf_secondfreqlimit DROP COLUMN server_id;
    ALTER TABLE waf_secondfreqlimit MODIFY waf_rule_id bigint NOT NULL;
    ALTER TABLE waf_secondfreqlimit ADD KEY waf_rule_id (waf_rule_id);
    ALTER TABLE waf_secondfreqlimit ADD CONSTRAINT waf_secondfreqlimit_waf_rule_fk FOREIGN KEY (waf_rule_id) REFERENCES waf_rule (id) ON DELETE CASCADE ON UPDATE CASCADE;

    ALTER TABLE waf_responsefreq ADD COLUMN waf_rule_id bigint NULL AFTER id;
    UPDATE waf_responsefreq w JOIN tmp_server_waf_rule m ON w.server_id = m.server_id SET w.waf_rule_id = m.waf_rule_id;
    ALTER TABLE waf_responsefreq DROP FOREIGN KEY waf_responsefreq_ibfk_1;
    ALTER TABLE waf_responsefreq DROP COLUMN server_id;
    ALTER TABLE waf_responsefreq MODIFY waf_rule_id bigint NOT NULL;
    ALTER TABLE waf_responsefreq ADD KEY waf_rule_id (waf_rule_id);
    ALTER TABLE waf_responsefreq ADD CONSTRAINT waf_responsefreq_waf_rule_fk FOREIGN KEY (waf_rule_id) REFERENCES waf_rule (id) ON DELETE CASCADE ON UPDATE CASCADE;

    ALTER TABLE waf_useragent ADD COLUMN waf_rule_id bigint NULL AFTER id;
    UPDATE waf_useragent w JOIN tmp_server_waf_rule m ON w.server_id = m.server_id SET w.waf_rule_id = m.waf_rule_id;
    ALTER TABLE waf_useragent DROP FOREIGN KEY waf_useragent_ibfk_1;
    ALTER TABLE waf_useragent DROP COLUMN server_id;
    ALTER TABLE waf_useragent MODIFY waf_rule_id bigint NOT NULL;
    ALTER TABLE waf_useragent ADD KEY waf_rule_id (waf_rule_id);
    ALTER TABLE waf_useragent ADD CONSTRAINT waf_useragent_waf_rule_fk FOREIGN KEY (waf_rule_id) REFERENCES waf_rule (id) ON DELETE CASCADE ON UPDATE CASCADE;

    DROP TEMPORARY TABLE IF EXISTS tmp_server_waf_rule;
  END IF;

  IF traffic_needs_migration > 0 THEN
    DROP TEMPORARY TABLE IF EXISTS tmp_server_waf_rule;
    CREATE TEMPORARY TABLE tmp_server_waf_rule (
      server_id bigint NOT NULL PRIMARY KEY,
      waf_rule_id bigint NOT NULL
    );

    INSERT INTO tmp_server_waf_rule (server_id, waf_rule_id)
    SELECT s.id, wr.id
    FROM servers s
    JOIN waf_rule wr ON wr.name = CONCAT('Server #', s.id, ' WAF');

    -- Bootstrap default sites for traffic data migration
    INSERT INTO sites (domain, status, waf_id)
    SELECT CONCAT('migrated-server-', s.id, '.local'), 'ENABLE', m.waf_rule_id
    FROM servers s
    LEFT JOIN tmp_server_waf_rule m ON m.server_id = s.id
    WHERE EXISTS (SELECT 1 FROM listening_ports lp WHERE lp.server_id = s.id)
       OR EXISTS (SELECT 1 FROM upstream_servers us WHERE us.server_id = s.id)
       OR EXISTS (SELECT 1 FROM cache_rules cr WHERE cr.server_id = s.id)
       OR EXISTS (SELECT 1 FROM compress_settings cs WHERE cs.server_id = s.id)
    ON DUPLICATE KEY UPDATE sites.waf_id = COALESCE(sites.waf_id, VALUES(waf_id));

    INSERT IGNORE INTO site_servers (site_id, server_id)
    SELECT si.id, s.id
    FROM servers s
    JOIN sites si ON si.domain = CONCAT('migrated-server-', s.id, '.local')
    WHERE EXISTS (SELECT 1 FROM listening_ports lp WHERE lp.server_id = s.id)
       OR EXISTS (SELECT 1 FROM upstream_servers us WHERE us.server_id = s.id)
       OR EXISTS (SELECT 1 FROM cache_rules cr WHERE cr.server_id = s.id)
       OR EXISTS (SELECT 1 FROM compress_settings cs WHERE cs.server_id = s.id);

    DROP TEMPORARY TABLE IF EXISTS tmp_server_site;
    CREATE TEMPORARY TABLE tmp_server_site (
      server_id bigint NOT NULL PRIMARY KEY,
      site_id bigint NOT NULL
    );

    INSERT INTO tmp_server_site (server_id, site_id)
    SELECT s.id, si.id
    FROM servers s
    JOIN sites si ON si.domain = CONCAT('migrated-server-', s.id, '.local');

    -- traffic tables: server_id -> site_id
    ALTER TABLE upstream_servers ADD COLUMN site_id bigint NULL AFTER id;
    UPDATE upstream_servers u JOIN tmp_server_site m ON u.server_id = m.server_id SET u.site_id = m.site_id;
    ALTER TABLE upstream_servers DROP FOREIGN KEY upstream_servers_ibfk_1;
    ALTER TABLE upstream_servers DROP COLUMN server_id;
    ALTER TABLE upstream_servers MODIFY site_id bigint NOT NULL;
    ALTER TABLE upstream_servers ADD KEY site_id (site_id);
    ALTER TABLE upstream_servers ADD CONSTRAINT upstream_servers_site_fk FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE ON UPDATE CASCADE;

    ALTER TABLE listening_ports ADD COLUMN site_id bigint NULL AFTER id;
    UPDATE listening_ports lp JOIN tmp_server_site m ON lp.server_id = m.server_id SET lp.site_id = m.site_id;
    ALTER TABLE listening_ports DROP FOREIGN KEY listening_ports_ibfk_1;
    ALTER TABLE listening_ports DROP COLUMN server_id;
    ALTER TABLE listening_ports MODIFY site_id bigint NOT NULL;
    ALTER TABLE listening_ports ADD KEY site_id (site_id);
    ALTER TABLE listening_ports ADD CONSTRAINT listening_ports_site_fk FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE ON UPDATE CASCADE;

    ALTER TABLE cache_rules ADD COLUMN site_id bigint NULL AFTER id;
    UPDATE cache_rules cr JOIN tmp_server_site m ON cr.server_id = m.server_id SET cr.site_id = m.site_id;
    ALTER TABLE cache_rules DROP FOREIGN KEY cache_rules_ibfk_1;
    ALTER TABLE cache_rules DROP COLUMN server_id;
    ALTER TABLE cache_rules MODIFY site_id bigint NOT NULL;
    ALTER TABLE cache_rules ADD KEY site_id (site_id);
    ALTER TABLE cache_rules ADD CONSTRAINT cache_rules_site_fk FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE ON UPDATE CASCADE;

    ALTER TABLE compress_settings ADD COLUMN site_id bigint NULL AFTER id;
    UPDATE compress_settings cs JOIN tmp_server_site m ON cs.server_id = m.server_id SET cs.site_id = m.site_id;
    ALTER TABLE compress_settings DROP FOREIGN KEY compress_settings_ibfk_1;
    ALTER TABLE compress_settings DROP INDEX server_id;
    ALTER TABLE compress_settings DROP COLUMN server_id;
    ALTER TABLE compress_settings MODIFY site_id bigint NOT NULL;
    ALTER TABLE compress_settings ADD UNIQUE KEY unique_site_compress (site_id);
    ALTER TABLE compress_settings ADD CONSTRAINT compress_settings_site_fk FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE ON UPDATE CASCADE;

    -- Link sites.waf_id to waf_rule when missing
    UPDATE sites s
    JOIN tmp_server_waf_rule m ON s.domain = CONCAT('migrated-server-', m.server_id, '.local')
    SET s.waf_id = m.waf_rule_id
    WHERE s.waf_id IS NULL;

    DROP TEMPORARY TABLE IF EXISTS tmp_server_waf_rule;
    DROP TEMPORARY TABLE IF EXISTS tmp_server_site;
  END IF;

  SELECT COUNT(*) INTO sites_fk_exists
  FROM information_schema.TABLE_CONSTRAINTS
  WHERE CONSTRAINT_SCHEMA = DATABASE()
    AND TABLE_NAME = 'sites'
    AND CONSTRAINT_NAME = 'sites_waf_rule_fk';

  IF sites_fk_exists = 0 THEN
    ALTER TABLE sites ADD CONSTRAINT sites_waf_rule_fk FOREIGN KEY (waf_id) REFERENCES waf_rule (id) ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END //
DELIMITER ;

CALL migrate_waf_rules_and_site_scope();
DROP PROCEDURE migrate_waf_rules_and_site_scope;
