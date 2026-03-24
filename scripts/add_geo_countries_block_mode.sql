-- L4 geo: when 1, geo_allow_countries is a blocklist; when 0 (default), it is an allowlist.
ALTER TABLE l4_ddos_defense
  ADD COLUMN geo_countries_block_mode TINYINT(1) NOT NULL DEFAULT 0
  AFTER geo_allow_countries;
