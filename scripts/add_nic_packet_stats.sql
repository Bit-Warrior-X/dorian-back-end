-- NIC / XDP packet counts and rates from Athens /server_traffic_stats.
-- packets_* = packets in the closed bucket; pps_* = packets / seconds since previous sample.

ALTER TABLE `server_traffic_stats`
  ADD COLUMN `packets_nic_rx` bigint(20) unsigned NOT NULL DEFAULT 0 AFTER `bandwidth_l7_tx`,
  ADD COLUMN `packets_nic_tx` bigint(20) unsigned NOT NULL DEFAULT 0 AFTER `packets_nic_rx`,
  ADD COLUMN `packets_nic_dropped` bigint(20) unsigned NOT NULL DEFAULT 0 AFTER `packets_nic_tx`,
  ADD COLUMN `packets_xdp_rx` bigint(20) unsigned NOT NULL DEFAULT 0 AFTER `packets_nic_dropped`,
  ADD COLUMN `packets_xdp_blocked` bigint(20) unsigned NOT NULL DEFAULT 0 AFTER `packets_xdp_rx`,
  ADD COLUMN `pps_nic_rx` double unsigned NOT NULL DEFAULT 0 AFTER `packets_xdp_blocked`,
  ADD COLUMN `pps_nic_tx` double unsigned NOT NULL DEFAULT 0 AFTER `pps_nic_rx`,
  ADD COLUMN `pps_nic_dropped` double unsigned NOT NULL DEFAULT 0 AFTER `pps_nic_tx`,
  ADD COLUMN `pps_xdp_rx` double unsigned NOT NULL DEFAULT 0 AFTER `pps_nic_dropped`,
  ADD COLUMN `pps_xdp_blocked` double unsigned NOT NULL DEFAULT 0 AFTER `pps_xdp_rx`;
