ALTER TABLE `sites`
  ADD COLUMN `certificate_error` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL AFTER `certificate_expiry`;
