-- Security items #3/#6: SSH host-key pinning and room for encrypted secrets.
-- Idempotent. Apply before deploying the API build that requires DATA_ENCRYPTION_KEY.
-- Existing plaintext servers.ssh_password / sites.ssl_cert_key values are encrypted
-- by the API itself on first start (they need the key, which SQL does not have).

CREATE TABLE IF NOT EXISTS `ssh_known_hosts` (
  `host_port` varchar(300) NOT NULL,
  `public_key` text NOT NULL,
  `fingerprint` varchar(128) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`host_port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Encrypted values are longer than the plaintext (prefix + nonce + tag, base64).
ALTER TABLE `servers` MODIFY `ssh_password` varchar(512) DEFAULT NULL;
