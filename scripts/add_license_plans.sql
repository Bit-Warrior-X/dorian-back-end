-- License tier catalog (monthly / annual prices shown in the panel).
-- Source of truth for LicenseTierSelector pricing.

CREATE TABLE IF NOT EXISTS `license_plans` (
  `id` varchar(32) NOT NULL,
  `title` varchar(64) NOT NULL,
  `tagline` varchar(128) DEFAULT NULL,
  `badge` varchar(64) DEFAULT NULL,
  `accent` varchar(32) NOT NULL DEFAULT 'trial',
  `monthly_price` decimal(12,2) NOT NULL DEFAULT 0.00,
  `annual_price` decimal(12,2) NOT NULL DEFAULT 0.00,
  `sort_order` int NOT NULL DEFAULT 0,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Prices aligned with modern CDN flat tiers (Cloudflare-class):
-- Trial = Free, L4 ≈ Pro, L7 ≈ Business, Unified = full-stack bundle.
-- Annual ≈ 20% off (billed as ~10 months).
INSERT INTO `license_plans` (`id`,`title`,`tagline`,`badge`,`accent`,`monthly_price`,`annual_price`,`sort_order`,`active`) VALUES
  ('Trial','Trial','Evaluation',NULL,'trial',0,0,0,1),
  ('L4','L4','Network protection',NULL,'l4',25,240,1,1),
  ('L7','L7','Application security',NULL,'l7',250,2400,2,1),
  ('Unified','Unified','Complete stack','Best value','unified',349,3348,3,1)
ON DUPLICATE KEY UPDATE
  title=VALUES(title),
  tagline=VALUES(tagline),
  badge=VALUES(badge),
  accent=VALUES(accent),
  monthly_price=VALUES(monthly_price),
  annual_price=VALUES(annual_price),
  sort_order=VALUES(sort_order),
  active=VALUES(active);
