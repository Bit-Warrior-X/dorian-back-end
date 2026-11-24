-- Idempotent seed for built-in L7 protection profiles (Off / Essential / Standard / Strict).
-- Prefer starting the API (EnsureProtectionProfiles) which also fills sub-rules on first create.
-- This script only ensures the waf_rule rows exist; sub-rules are filled by the API seed on next boot
-- when the pack still has zero child rules.

INSERT INTO waf_rule (name, role)
SELECT 'Protection — Off', 'predefined'
WHERE NOT EXISTS (
  SELECT 1 FROM waf_rule WHERE name = 'Protection — Off' AND role = 'predefined'
);

INSERT INTO waf_rule (name, role)
SELECT 'Protection — Essential', 'predefined'
WHERE NOT EXISTS (
  SELECT 1 FROM waf_rule WHERE name = 'Protection — Essential' AND role = 'predefined'
);

INSERT INTO waf_rule (name, role)
SELECT 'Protection — Standard', 'predefined'
WHERE NOT EXISTS (
  SELECT 1 FROM waf_rule WHERE name = 'Protection — Standard' AND role = 'predefined'
);

INSERT INTO waf_rule (name, role)
SELECT 'Protection — Strict', 'predefined'
WHERE NOT EXISTS (
  SELECT 1 FROM waf_rule WHERE name = 'Protection — Strict' AND role = 'predefined'
);
