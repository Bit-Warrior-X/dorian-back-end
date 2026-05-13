-- Migrate servers.license_type from the legacy enum ('Enterprise','Professional','Trial')
-- to the new license-tier enum ('Trial','L4','L7','Unified').
--
-- Rows whose license_type was 'Enterprise' or 'Professional' are remapped to 'Unified'
-- so existing servers continue to deploy under the highest tier after the migration.
-- Adjust the UPDATE statement before running if you want a different mapping
-- (e.g. 'Professional' -> 'L7').

-- 1. Widen the column so both legacy and new values are accepted during the rewrite.
ALTER TABLE servers
  MODIFY COLUMN license_type
    ENUM('Trial','L4','L7','Unified','Enterprise','Professional')
    NULL;

-- 2. Remap legacy labels to the new tier names.
UPDATE servers SET license_type = 'Unified' WHERE license_type = 'Enterprise';
UPDATE servers SET license_type = 'Unified' WHERE license_type = 'Professional';

-- 3. Drop the legacy values from the enum (preserve original DEFAULT 'Trial').
ALTER TABLE servers
  MODIFY COLUMN license_type
    ENUM('Trial','L4','L7','Unified')
    NULL DEFAULT 'Trial';
