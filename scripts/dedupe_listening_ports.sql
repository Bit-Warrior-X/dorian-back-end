-- One-time: collapse duplicate listening_ports and enforce uniqueness.
CREATE TEMPORARY TABLE IF NOT EXISTS lp_keepers AS
SELECT lp.server_id, lp.port, lp.protocol,
  COALESCE(
    (SELECT MIN(lp2.id) FROM listening_ports lp2
      INNER JOIN site_listening_ports slp ON slp.listening_port_id = lp2.id
      WHERE lp2.server_id = lp.server_id AND lp2.port = lp.port AND lp2.protocol = lp.protocol),
    MIN(lp.id)
  ) AS keeper_id
FROM listening_ports lp
GROUP BY lp.server_id, lp.port, lp.protocol;

UPDATE site_listening_ports slp
INNER JOIN listening_ports lp ON lp.id = slp.listening_port_id
INNER JOIN lp_keepers k ON k.server_id = lp.server_id AND k.port = lp.port AND k.protocol = lp.protocol
SET slp.listening_port_id = k.keeper_id
WHERE slp.listening_port_id <> k.keeper_id;

DELETE lp FROM listening_ports lp
INNER JOIN lp_keepers k ON k.server_id = lp.server_id AND k.port = lp.port AND k.protocol = lp.protocol
WHERE lp.id <> k.keeper_id;

SET @exists := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'listening_ports'
    AND index_name = 'listening_ports_server_port_protocol'
);
SET @sql := IF(@exists = 0,
  'ALTER TABLE listening_ports ADD UNIQUE KEY listening_ports_server_port_protocol (server_id, port, protocol)',
  'SELECT ''listening_ports unique key already exists'' AS note');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
