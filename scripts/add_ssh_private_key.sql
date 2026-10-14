-- Optional SSH private key (and passphrase) per edge, used by the panel's own SSH
-- connections. Both columns hold values encrypted with DATA_ENCRYPTION_KEY.
-- Idempotent (MariaDB 10.0.2+).

ALTER TABLE `servers`
  ADD COLUMN IF NOT EXISTS `ssh_private_key` text DEFAULT NULL AFTER `ssh_password`,
  ADD COLUMN IF NOT EXISTS `ssh_key_passphrase` varchar(1024) DEFAULT NULL AFTER `ssh_private_key`;
