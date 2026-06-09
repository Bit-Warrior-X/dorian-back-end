-- --------------------------------------------------------
-- Host:                         192.168.147.3
-- Server version:               8.0.45-0ubuntu0.24.04.1 - (Ubuntu)
-- Server OS:                    Linux
-- HeidiSQL Version:             12.11.0.7065
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


-- Dumping database structure for cdnproxy
DROP DATABASE IF EXISTS `cdnproxy`;
CREATE DATABASE IF NOT EXISTS `cdnproxy` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `cdnproxy`;

-- Dumping structure for table cdnproxy.blacklist
DROP TABLE IF EXISTS `blacklist`;
CREATE TABLE IF NOT EXISTS `blacklist` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `ip_address` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `url` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `geolocation` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `reason` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `server` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `ttl` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `trigger_rule` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `created_at` timestamp NULL DEFAULT (now()),
  `expire_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()),
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `blacklist_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1011 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for procedure cdnproxy.clone_ddos_settings
DROP PROCEDURE IF EXISTS `clone_ddos_settings`;
DELIMITER //
CREATE PROCEDURE `clone_ddos_settings`(
    IN source_server_id INT,
    IN target_server_id INT
)
BEGIN
    DECLARE source_l4_id INT;
    DECLARE new_l4_id INT;
    
    -- Get source server's l4_id
    SELECT l4_id INTO source_l4_id
    FROM servers WHERE id = source_server_id;
    
    IF source_l4_id IS NULL THEN
        SIGNAL SQLSTATE '45000' 
        SET MESSAGE_TEXT = 'Source server does not have DDoS settings';
    END IF;
    
    -- Clone the settings
    INSERT INTO l4_ddos_defense (
        dev, attach_mode, black_ip_duration,
        syn_valid, syn_threshold, syn_burst_pkt, syn_burst_count_per_sec,
        syn_fixed_threshold, syn_fixed_check_duration, challenge_timeout,
        syn_protection_duration,
        ack_valid, ack_threshold, ack_burst_pkt, ack_burst_count_per_sec,
        ack_fixed_threshold, ack_fixed_check_duration, ack_protection_duration,
        rst_valid, rst_threshold, rst_burst_pkt, rst_burst_count_per_sec,
        rst_fixed_threshold, rst_fixed_check_duration, rst_protection_duration,
        icmp_valid, icmp_threshold, icmp_burst_pkt, icmp_burst_count_per_sec,
        icmp_fixed_threshold, icmp_fixed_check_duration, icmp_protection_duration,
        udp_valid, udp_threshold, udp_burst_pkt, udp_burst_count_per_sec,
        udp_fixed_threshold, udp_fixed_check_duration, udp_protection_duration,
        gre_valid, gre_threshold, gre_burst_pkt, gre_burst_count_per_sec,
        gre_fixed_threshold, gre_fixed_check_duration, gre_protection_duration,
        tcp_seg_check,
        geo_check, geo_db_ipv4_path, geo_db_location_path, geo_allow_countries,
        tcp_connection_limit_check, tcp_connection_limit_cnt
    )
    SELECT 
        dev, attach_mode, black_ip_duration,
        syn_valid, syn_threshold, syn_burst_pkt, syn_burst_count_per_sec,
        syn_fixed_threshold, syn_fixed_check_duration, challenge_timeout,
        syn_protection_duration,
        ack_valid, ack_threshold, ack_burst_pkt, ack_burst_count_per_sec,
        ack_fixed_threshold, ack_fixed_check_duration, ack_protection_duration,
        rst_valid, rst_threshold, rst_burst_pkt, rst_burst_count_per_sec,
        rst_fixed_threshold, rst_fixed_check_duration, rst_protection_duration,
        icmp_valid, icmp_threshold, icmp_burst_pkt, icmp_burst_count_per_sec,
        icmp_fixed_threshold, icmp_fixed_check_duration, icmp_protection_duration,
        udp_valid, udp_threshold, udp_burst_pkt, udp_burst_count_per_sec,
        udp_fixed_threshold, udp_fixed_check_duration, udp_protection_duration,
        gre_valid, gre_threshold, gre_burst_pkt, gre_burst_count_per_sec,
        gre_fixed_threshold, gre_fixed_check_duration, gre_protection_duration,
        tcp_seg_check,
        geo_check, geo_db_ipv4_path, geo_db_location_path, geo_allow_countries,
        tcp_connection_limit_check, tcp_connection_limit_cnt
    FROM l4_ddos_defense
    WHERE id = source_l4_id;
    
    SET new_l4_id = LAST_INSERT_ID();
    
    -- Update target server
    UPDATE servers 
    SET l4_id = new_l4_id 
    WHERE id = target_server_id;
    
    -- Delete old settings if target server had them
    DELETE FROM l4_ddos_defense 
    WHERE id = (SELECT l4_id FROM (SELECT l4_id FROM servers WHERE id = target_server_id) AS old);
    
    SELECT new_l4_id AS cloned_settings_id;
END//
DELIMITER ;

-- Dumping structure for table cdnproxy.country_request_stats
DROP TABLE IF EXISTS `country_request_stats`;
CREATE TABLE IF NOT EXISTS `country_request_stats` (
  `server_id` bigint NOT NULL,
  `bucket_ts` datetime NOT NULL,
  `country_code` char(2) NOT NULL,
  `request_count` int unsigned NOT NULL DEFAULT '0',
  `blocked_request_count` int unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`server_id`,`bucket_ts`,`country_code`),
  KEY `idx_bucket` (`bucket_ts`),
  KEY `idx_server_bucket` (`server_id`,`bucket_ts`),
  CONSTRAINT `country_request_stats_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for procedure cdnproxy.GenerateCountrySampleStats
DROP PROCEDURE IF EXISTS `GenerateCountrySampleStats`;
DELIMITER //
CREATE PROCEDURE `GenerateCountrySampleStats`()
BEGIN
    DECLARE v_server_id BIGINT;
    DECLARE v_bucket_ts DATETIME;
    DECLARE v_country_index INT;
    DECLARE v_interval_minutes INT DEFAULT 145;
    DECLARE v_time_counter INT;
    DECLARE v_country_counter INT;
    DECLARE v_country_count INT;
    DECLARE v_done INT DEFAULT FALSE;
    
    -- Country codes with realistic traffic patterns and blocking rates
    DECLARE country_data TEXT DEFAULT 
        'US:2500:0.02,CN:1800:0.05,IN:1200:0.01,GB:900:0.01,DE:800:0.01,FR:750:0.01,JP:700:0.02,BR:600:0.03,RU:550:0.10,CA:500:0.01,AU:450:0.01,KR:400:0.02,MX:350:0.03,IT:300:0.01,ES:280:0.01,NL:250:0.01,SE:220:0.01,SG:200:0.01,AE:180:0.02,ZA:150:0.04,TR:120:0.03,PL:110:0.01,ID:100:0.02,TH:90:0.01,VN:80:0.01,PH:70:0.02,EG:60:0.05,SA:50:0.03,NG:40:0.04,KE:30:0.03';
    
    DECLARE current_country_code CHAR(2);
    DECLARE current_base_traffic INT;
    DECLARE current_block_rate DECIMAL(3,2);
    DECLARE country_hash BINARY(16);
    DECLARE v_request_count INT;
    DECLARE v_blocked_count INT;
    
    -- Cursor for servers
    DECLARE v_server_cursor CURSOR FOR SELECT id FROM servers LIMIT 5;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;
    
    -- Calculate country count
    SET v_country_count = (LENGTH(country_data) - LENGTH(REPLACE(country_data, ',', '')) + 1);
    
    OPEN v_server_cursor;
    
    server_loop: LOOP
        FETCH v_server_cursor INTO v_server_id;
        IF v_done THEN
            LEAVE server_loop;
        END IF;
        
        -- Reset interval for each server
        SET v_interval_minutes = 145;
        SET v_time_counter = 0;
        
        -- Generate data for 30 time buckets (5-minute intervals)
        WHILE v_time_counter < 30 DO
            -- Calculate bucket time (going backwards)
            SET v_bucket_ts = NOW() - INTERVAL v_interval_minutes MINUTE;
            -- Round to nearest 5-minute bucket
            SET v_bucket_ts = FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(v_bucket_ts) / 300) * 300);
            
            -- Insert 4-10 different countries per time bucket
            SET v_country_counter = 0;
            SET v_country_index = FLOOR(RAND() * (v_country_count - 8)) + 1;
            
            WHILE v_country_counter < FLOOR(RAND() * 7) + 4 DO
                -- Extract country data from comma-separated list
                SET @country_item = SUBSTRING_INDEX(
                    SUBSTRING_INDEX(country_data, ',', v_country_index), 
                    ',', 
                    -1
                );
                
                -- Parse country code, base traffic, and block rate
                SET current_country_code = SUBSTRING_INDEX(@country_item, ':', 1);
                SET current_base_traffic = CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(@country_item, ':', 2), ':', -1) AS UNSIGNED);
                SET current_block_rate = CAST(SUBSTRING_INDEX(@country_item, ':', -1) AS DECIMAL(3,2));
                
                -- Generate traffic with some randomness (±30%) and server-specific multiplier
                SET v_request_count = FLOOR(
                    current_base_traffic * 
                    (0.7 + (RAND() * 0.6)) *  -- 70-130% of base traffic
                    (0.8 + (MOD(v_server_id, 4) * 0.1))  -- Server-specific variation
                );
                
                -- Generate blocked requests with some randomness
                SET v_blocked_count = FLOOR(
                    v_request_count * 
                    current_block_rate * 
                    (0.8 + (RAND() * 0.4))  -- 80-120% of expected block rate
                );
                
                -- Ensure blocked count doesn't exceed request count
                IF v_blocked_count > v_request_count THEN
                    SET v_blocked_count = FLOOR(v_request_count * 0.9);
                END IF;
                
                -- Ensure minimum values
                SET v_request_count = GREATEST(1, v_request_count);
                SET v_blocked_count = LEAST(v_request_count, v_blocked_count);
                
                -- Insert record
                INSERT INTO `country_request_stats` (
                    `server_id`, 
                    `bucket_ts`, 
                    `country_code`, 
                    `request_count`,
                    `blocked_request_count`
                ) VALUES (
                    v_server_id,
                    v_bucket_ts,
                    current_country_code,
                    v_request_count,
                    v_blocked_count
                ) ON DUPLICATE KEY UPDATE 
                    request_count = request_count + VALUES(request_count),
                    blocked_request_count = blocked_request_count + VALUES(blocked_request_count);
                
                SET v_country_counter = v_country_counter + 1;
                SET v_country_index = v_country_index + 1;
                
                -- Wrap around if we exceed the country list
                IF v_country_index > v_country_count THEN
                    SET v_country_index = 1;
                END IF;
            END WHILE;
            
            SET v_time_counter = v_time_counter + 1;
            SET v_interval_minutes = v_interval_minutes - 5;
        END WHILE;
    END LOOP;
    
    CLOSE v_server_cursor;
    
    -- Return summary
    SELECT 
        CONCAT('Generated country request data for ', 
               (SELECT COUNT(DISTINCT server_id) FROM country_request_stats WHERE bucket_ts >= NOW() - INTERVAL 150 MINUTE),
               ' servers') AS result;
END//
DELIMITER ;

-- Dumping structure for procedure cdnproxy.GenerateISPRequestStats
DROP PROCEDURE IF EXISTS `GenerateISPRequestStats`;
DELIMITER //
CREATE PROCEDURE `GenerateISPRequestStats`()
BEGIN
    DECLARE v_server_id BIGINT;
    DECLARE v_bucket_ts DATETIME;
    DECLARE v_isp_index INT;
    DECLARE v_interval_minutes INT DEFAULT 145;
    DECLARE v_time_counter INT;
    DECLARE v_isp_counter INT;
    DECLARE v_isp_count INT;
    DECLARE v_done INT DEFAULT FALSE;
    DECLARE isp_names TEXT DEFAULT 'Comcast Cable,AT&T Services,Verizon Fios,Spectrum,T-Mobile USA,Google Fiber,CenturyLink,Charter Communications,Cox Communications,Frontier Communications,Windstream,HughesNet,Viasat,Altice USA,Mediacom';
    DECLARE current_isp TEXT;
    DECLARE isp_hash BINARY(16);
    
    -- Cursor must be declared after all variables
    DECLARE v_server_cursor CURSOR FOR SELECT id FROM servers LIMIT 10;
    -- Handler must be declared after cursor
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;
    
    -- Calculate ISP count
    SET v_isp_count = (LENGTH(isp_names) - LENGTH(REPLACE(isp_names, ',', '')) + 1);
    
    OPEN v_server_cursor;
    
    server_loop: LOOP
        FETCH v_server_cursor INTO v_server_id;
        IF v_done THEN
            LEAVE server_loop;
        END IF;
        
        -- Reset interval for each server
        SET v_interval_minutes = 145;
        SET v_time_counter = 0;
        
        -- Generate data for 30 time buckets (5-minute intervals)
        WHILE v_time_counter < 30 DO
            SET v_bucket_ts = NOW() - INTERVAL v_interval_minutes MINUTE;
            
            -- Insert 3-8 different ISPs per time bucket
            SET v_isp_counter = 0;
            SET v_isp_index = FLOOR(RAND() * (v_isp_count - 3)) + 1;
            
            WHILE v_isp_counter < FLOOR(RAND() * 6) + 3 DO
                -- Extract ISP name from comma-separated list
                SET current_isp = SUBSTRING_INDEX(
                    SUBSTRING_INDEX(isp_names, ',', v_isp_index), 
                    ',', 
                    -1
                );
                
                -- Generate deterministic hash for this ISP
                SET isp_hash = UNHEX(MD5(CONCAT(v_server_id, v_bucket_ts, current_isp)));
                
                INSERT INTO `isp_request_stats` (
                    `server_id`, 
                    `bucket_ts`, 
                    `isp_hash`, 
                    `request_isp`, 
                    `request_count`
                ) VALUES (
                    v_server_id,
                    v_bucket_ts,
                    isp_hash,
                    current_isp,
                    FLOOR(RAND() * 1000) + 1
                ) ON DUPLICATE KEY UPDATE 
                    request_count = request_count + VALUES(request_count);
                
                SET v_isp_counter = v_isp_counter + 1;
                SET v_isp_index = v_isp_index + 1;
                
                -- Wrap around if we exceed the ISP list
                IF v_isp_index > v_isp_count THEN
                    SET v_isp_index = 1;
                END IF;
            END WHILE;
            
            SET v_time_counter = v_time_counter + 1;
            SET v_interval_minutes = v_interval_minutes - 5;
        END WHILE;
    END LOOP;
    
    CLOSE v_server_cursor;
END//
DELIMITER ;

-- Dumping structure for procedure cdnproxy.Generatel4AttackSample
DROP PROCEDURE IF EXISTS `Generatel4AttackSample`;
DELIMITER //
CREATE PROCEDURE `Generatel4AttackSample`()
BEGIN
    DECLARE v_server_id BIGINT;
    DECLARE v_attack_counter INT DEFAULT 0;
    DECLARE v_max_attacks INT DEFAULT 100;
    DECLARE v_done INT DEFAULT FALSE;
    
    -- Common attack types for L4/Layer 4 attacks
    DECLARE attack_types TEXT DEFAULT 'SYN Flood,UDP Flood,ICMP Flood,HTTP Flood,Slowloris,SSH Brute Force,RDP Brute Force,DNS Amplification,NTP Amplification,Memcached Amplification,Ping of Death,Teardrop,Smurf Attack,Fragmentation Attack,ACK Flood,Random Flag Flood,Christmas Tree Attack,Land Attack,Null Scan,Xmas Scan,FIN Scan';
    
    -- Common source IP ranges (some malicious, some random)
    DECLARE ip_ranges TEXT DEFAULT 
        '185.122.204.,194.87.148.,91.243.119.,5.188.210.,103.143.174.,45.142.212.,80.82.64.,198.51.100.,203.0.113.,192.0.2.,10.,172.16.,192.168.,'
        '223.255.255.,119.28.112.,47.244.175.,106.12.134.,123.206.89.,139.199.125.,101.132.145.,'
        '188.166.221.,159.89.174.,167.99.165.,138.197.189.,165.227.109.,'
        '45.77.201.,149.28.135.,209.97.175.,178.128.211.,159.203.43.';
    
    DECLARE current_attack_type VARCHAR(64);
    DECLARE current_source_ip VARCHAR(500);
    DECLARE v_attack_type_count INT;
    DECLARE v_ip_range_count INT;
    DECLARE v_ip_suffix INT;
    DECLARE v_attack_index INT;
    DECLARE v_ip_range_index INT;
    
    -- Cursor for servers
    DECLARE v_server_cursor CURSOR FOR SELECT id FROM servers LIMIT 5;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;
    
    -- Calculate counts
    SET v_attack_type_count = (LENGTH(attack_types) - LENGTH(REPLACE(attack_types, ',', '')) + 1);
    SET v_ip_range_count = (LENGTH(ip_ranges) - LENGTH(REPLACE(ip_ranges, ',', '')) + 1);
    
    OPEN v_server_cursor;
    
    -- Start with some initial attacks
    SET v_attack_counter = 0;
    
    server_loop: LOOP
        FETCH v_server_cursor INTO v_server_id;
        IF v_done OR v_attack_counter >= v_max_attacks THEN
            LEAVE server_loop;
        END IF;
        
        -- Generate 5-15 attacks per server
        SET @attacks_per_server = FLOOR(RAND() * 11) + 5;
        SET @attack_num = 0;
        
        WHILE @attack_num < @attacks_per_server AND v_attack_counter < v_max_attacks DO
            -- Select random attack type
            SET v_attack_index = FLOOR(RAND() * v_attack_type_count) + 1;
            SET current_attack_type = SUBSTRING_INDEX(
                SUBSTRING_INDEX(attack_types, ',', v_attack_index), 
                ',', 
                -1
            );
            
            -- Select random IP range
            SET v_ip_range_index = FLOOR(RAND() * v_ip_range_count) + 1;
            SET current_source_ip = SUBSTRING_INDEX(
                SUBSTRING_INDEX(ip_ranges, ',', v_ip_range_index), 
                ',', 
                -1
            );
            
            -- Add random suffix (0-255) unless it's a private range
            IF current_source_ip NOT IN ('10.', '172.16.', '192.168.') THEN
                SET v_ip_suffix = FLOOR(RAND() * 256);
                SET current_source_ip = CONCAT(current_source_ip, v_ip_suffix);
            ELSE
                -- For private IPs, add appropriate suffixes
                IF current_source_ip = '10.' THEN
                    SET current_source_ip = CONCAT('10.', FLOOR(RAND() * 256), '.', FLOOR(RAND() * 256), '.', FLOOR(RAND() * 256));
                ELSEIF current_source_ip = '172.16.' THEN
                    SET current_source_ip = CONCAT('172.16.', FLOOR(RAND() * 16), '.', FLOOR(RAND() * 256));
                ELSE -- 192.168.
                    SET current_source_ip = CONCAT('192.168.', FLOOR(RAND() * 256), '.', FLOOR(RAND() * 256));
                END IF;
            END IF;
            
            -- Sometimes add multiple IPs (botnet simulation)
            IF RAND() < 0.2 THEN
                SET current_source_ip = CONCAT(current_source_ip, ',');
                
                -- Add 1-3 more IPs
                SET @extra_ips = FLOOR(RAND() * 3) + 1;
                SET @ip_num = 0;
                
                WHILE @ip_num < @extra_ips DO
                    SET v_ip_range_index = FLOOR(RAND() * v_ip_range_count) + 1;
                    SET @extra_ip = SUBSTRING_INDEX(
                        SUBSTRING_INDEX(ip_ranges, ',', v_ip_range_index), 
                        ',', 
                        -1
                    );
                    
                    IF @extra_ip NOT IN ('10.', '172.16.', '192.168.') THEN
                        SET @extra_ip = CONCAT(@extra_ip, FLOOR(RAND() * 256));
                    END IF;
                    
                    SET current_source_ip = CONCAT(current_source_ip, @extra_ip);
                    
                    IF @ip_num < @extra_ips - 1 THEN
                        SET current_source_ip = CONCAT(current_source_ip, ',');
                    END IF;
                    
                    SET @ip_num = @ip_num + 1;
                END WHILE;
            END IF;
            
            -- Insert attack record with recent timestamp
            INSERT INTO `l4_live_attack` (
                `server_id`, 
                `source_ip`, 
                `attack_type`,
                `created_at`,
                `updated_at`
            ) VALUES (
                v_server_id,
                current_source_ip,
                current_attack_type,
                DATE_SUB(NOW(), INTERVAL FLOOR(RAND() * 1440) MINUTE),  -- Random time in last 24 hours
                NOW()
            );
            
            SET v_attack_counter = v_attack_counter + 1;
            SET @attack_num = @attack_num + 1;
            
            -- Simulate some attacks being updated recently
            IF RAND() < 0.3 AND v_attack_counter > 10 THEN
                UPDATE `l4_live_attack` 
                SET `updated_at` = DATE_SUB(NOW(), INTERVAL FLOOR(RAND() * 60) MINUTE)
                WHERE `id` = LAST_INSERT_ID();
            END IF;
        END WHILE;
    END LOOP;
    
    CLOSE v_server_cursor;
    
    -- Return summary
    SELECT 
        CONCAT('Generated ', v_attack_counter, ' live attack records') AS result,
        (SELECT COUNT(DISTINCT server_id) FROM l4_live_attack) AS servers_affected,
        (SELECT COUNT(DISTINCT attack_type) FROM l4_live_attack) AS attack_types_logged;
END//
DELIMITER ;

-- Dumping structure for procedure cdnproxy.GenerateL4AttackStats
DROP PROCEDURE IF EXISTS `GenerateL4AttackStats`;
DELIMITER //
CREATE PROCEDURE `GenerateL4AttackStats`()
BEGIN
    DECLARE v_server_id BIGINT;
    DECLARE v_bucket_ts DATETIME;
    DECLARE v_interval_minutes INT DEFAULT 145;
    DECLARE v_time_counter INT;
    DECLARE v_done INT DEFAULT FALSE;
    
    -- Traffic patterns for different times
    DECLARE v_base_traffic BIGINT UNSIGNED;
    DECLARE v_attack_factor DECIMAL(3,2);
    DECLARE v_block_rate DECIMAL(3,2);
    
    -- Protocol distributions
    DECLARE v_tcp_ratio DECIMAL(3,2);
    DECLARE v_udp_ratio DECIMAL(3,2);
    DECLARE v_icmp_ratio DECIMAL(3,2);
    DECLARE v_gre_ratio DECIMAL(3,2);
    DECLARE v_other_ratio DECIMAL(3,2);
    
    -- TCP flag distributions
    DECLARE v_tcp_syn_ratio DECIMAL(3,2);
    DECLARE v_tcp_ack_ratio DECIMAL(3,2);
    DECLARE v_tcp_rst_ratio DECIMAL(3,2);
    
    -- Calculated values
    DECLARE v_total_traffic BIGINT UNSIGNED;
    DECLARE v_allowed_traffic BIGINT UNSIGNED;
    DECLARE v_blocked_traffic BIGINT UNSIGNED;
    DECLARE v_tcp_traffic BIGINT UNSIGNED;
    DECLARE v_udp_traffic BIGINT UNSIGNED;
    DECLARE v_icmp_traffic BIGINT UNSIGNED;
    DECLARE v_gre_traffic BIGINT UNSIGNED;
    DECLARE v_other_traffic BIGINT UNSIGNED;
    DECLARE v_tcp_syn_traffic BIGINT UNSIGNED;
    DECLARE v_tcp_ack_traffic BIGINT UNSIGNED;
    DECLARE v_tcp_rst_traffic BIGINT UNSIGNED;
    
    -- Cursor for servers
    DECLARE v_server_cursor CURSOR FOR SELECT id FROM servers LIMIT 5;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;
    
    OPEN v_server_cursor;
    
    server_loop: LOOP
        FETCH v_server_cursor INTO v_server_id;
        IF v_done THEN
            LEAVE server_loop;
        END IF;
        
        -- Reset interval for each server
        SET v_interval_minutes = 145;
        SET v_time_counter = 0;
        
        -- Generate data for 30 time buckets (5-minute intervals over ~2.5 hours)
        WHILE v_time_counter < 30 DO
            -- Calculate bucket time (going backwards)
            SET v_bucket_ts = NOW() - INTERVAL v_interval_minutes MINUTE;
            SET v_bucket_ts = FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(v_bucket_ts) / 300) * 300);
            
            -- Determine traffic patterns based on time and server
            SET @hour = HOUR(v_bucket_ts);
            SET @minute = MINUTE(v_bucket_ts);
            SET @server_mod = MOD(v_server_id, 3);
            
            -- Base traffic varies by time of day (in Gbps converted to bytes)
            SET v_base_traffic = CASE 
                WHEN @hour BETWEEN 0 AND 5 THEN 5000000000    -- Low traffic overnight (5GB)
                WHEN @hour BETWEEN 6 AND 9 THEN 15000000000   -- Morning rush (15GB)
                WHEN @hour BETWEEN 10 AND 17 THEN 20000000000 -- Daytime peak (20GB)
                WHEN @hour BETWEEN 18 AND 21 THEN 25000000000 -- Evening peak (25GB)
                ELSE 10000000000                              -- Late night (10GB)
            END;
            
            -- Attack factor (0.1 to 3.0) - higher during certain times
            SET v_attack_factor = CASE 
                WHEN @hour BETWEEN 2 AND 4 THEN 0.5 + (RAND() * 1.0)   -- Low attack period
                WHEN @hour BETWEEN 9 AND 11 THEN 1.5 + (RAND() * 1.5)  -- Morning attacks
                WHEN @hour BETWEEN 14 AND 16 THEN 2.0 + (RAND() * 1.0) -- Afternoon DDoS
                WHEN @hour BETWEEN 19 AND 21 THEN 1.8 + (RAND() * 1.2) -- Evening attacks
                ELSE 0.8 + (RAND() * 0.7)                             -- Normal periods
            END;
            
            -- Block rate varies by server and time (0.01 to 0.30)
            SET v_block_rate = 0.05 + (@server_mod * 0.08) + (RAND() * 0.12);
            
            -- Protocol distribution (sums to 1.0)
            SET v_tcp_ratio = 0.65 + (RAND() * 0.20);   -- 65-85% TCP
            SET v_udp_ratio = 0.10 + (RAND() * 0.15);   -- 10-25% UDP
            SET v_icmp_ratio = 0.02 + (RAND() * 0.03);  -- 2-5% ICMP
            SET v_gre_ratio = 0.01 + (RAND() * 0.02);   -- 1-3% GRE
            SET v_other_ratio = 1.0 - (v_tcp_ratio + v_udp_ratio + v_icmp_ratio + v_gre_ratio);
            
            -- TCP flag distribution (within TCP traffic)
            SET v_tcp_syn_ratio = 0.40 + (RAND() * 0.30);  -- 40-70% SYN (including SYN floods)
            SET v_tcp_ack_ratio = 0.20 + (RAND() * 0.20);  -- 20-40% ACK
            SET v_tcp_rst_ratio = 0.05 + (RAND() * 0.10);  -- 5-15% RST
            -- Remaining TCP is FIN, PSH, URG, etc.
            
            -- Calculate total traffic with attack factor
            SET v_total_traffic = FLOOR(v_base_traffic * v_attack_factor * (0.9 + RAND() * 0.2));
            
            -- Calculate blocked traffic
            SET v_blocked_traffic = FLOOR(v_total_traffic * v_block_rate * (0.8 + RAND() * 0.4));
            SET v_allowed_traffic = v_total_traffic - v_blocked_traffic;
            
            -- Calculate protocol-specific traffic
            SET v_tcp_traffic = FLOOR(v_total_traffic * v_tcp_ratio);
            SET v_udp_traffic = FLOOR(v_total_traffic * v_udp_ratio);
            SET v_icmp_traffic = FLOOR(v_total_traffic * v_icmp_ratio);
            SET v_gre_traffic = FLOOR(v_total_traffic * v_gre_ratio);
            SET v_other_traffic = v_total_traffic - (v_tcp_traffic + v_udp_traffic + v_icmp_traffic + v_gre_traffic);
            
            -- Calculate TCP flag traffic (within TCP traffic)
            SET v_tcp_syn_traffic = FLOOR(v_tcp_traffic * v_tcp_syn_ratio);
            SET v_tcp_ack_traffic = FLOOR(v_tcp_traffic * v_tcp_ack_ratio);
            SET v_tcp_rst_traffic = FLOOR(v_tcp_traffic * v_tcp_rst_ratio);
            
            -- Insert record
            INSERT INTO `l4_attack_stats` (
                `server_id`, 
                `bucket_ts`, 
                `total_traffic`, 
                `allowed_traffic`, 
                `blocked_traffic`,
                `tcp`, 
                `udp`, 
                `icmp`, 
                `gre`, 
                `other`,
                `tcp_syn`, 
                `tcp_ack`, 
                `tcp_rst`
            ) VALUES (
                v_server_id,
                v_bucket_ts,
                v_total_traffic,
                v_allowed_traffic,
                v_blocked_traffic,
                v_tcp_traffic,
                v_udp_traffic,
                v_icmp_traffic,
                v_gre_traffic,
                v_other_traffic,
                v_tcp_syn_traffic,
                v_tcp_ack_traffic,
                v_tcp_rst_traffic
            ) ON DUPLICATE KEY UPDATE 
                total_traffic = VALUES(total_traffic),
                allowed_traffic = VALUES(allowed_traffic),
                blocked_traffic = VALUES(blocked_traffic),
                tcp = VALUES(tcp),
                udp = VALUES(udp),
                icmp = VALUES(icmp),
                gre = VALUES(gre),
                other = VALUES(other),
                tcp_syn = VALUES(tcp_syn),
                tcp_ack = VALUES(tcp_ack),
                tcp_rst = VALUES(tcp_rst);
            
            SET v_time_counter = v_time_counter + 1;
            SET v_interval_minutes = v_interval_minutes - 5;
        END WHILE;
    END LOOP;
    
    CLOSE v_server_cursor;
    
    -- Return summary
    SELECT 
        CONCAT('Generated L4 attack stats for ', 
               (SELECT COUNT(DISTINCT server_id) FROM l4_attack_stats WHERE bucket_ts >= NOW() - INTERVAL 150 MINUTE),
               ' servers') AS RESULT;
END//
DELIMITER ;

-- Dumping structure for procedure cdnproxy.GenerateRefererRequestStats
DROP PROCEDURE IF EXISTS `GenerateRefererRequestStats`;
DELIMITER //
CREATE PROCEDURE `GenerateRefererRequestStats`()
BEGIN
    DECLARE v_server_id BIGINT;
    DECLARE v_bucket_ts DATETIME;
    DECLARE v_time_counter INT DEFAULT 0;
    DECLARE v_referer_counter INT;
    DECLARE v_interval_minutes INT DEFAULT 145;
    DECLARE referer_list TEXT DEFAULT 'https://www.google.com/,https://www.bing.com/,https://www.yahoo.com/,https://duckduckgo.com/,https://www.reddit.com/,https://www.facebook.com/,https://twitter.com/,https://www.linkedin.com/,https://github.com/,https://stackoverflow.com/,https://medium.com/,https://news.ycombinator.com/,https://www.amazon.com/,https://www.youtube.com/,https://www.instagram.com/,direct,unknown,https://example.com/,https://docs.example.com/,https://api.example.com/';
    DECLARE referer_array TEXT;
    DECLARE current_referer TEXT;
    DECLARE total_referers INT;
    DECLARE referer_hash BINARY(16);
    
    -- Get a random server ID from the servers table
    SELECT id INTO v_server_id FROM servers ORDER BY RAND() LIMIT 1;
    
    -- If no servers exist, use a default value
    IF v_server_id IS NULL THEN
        SET v_server_id = 31;
    END IF;
    
    SET referer_array = referer_list;
    SET total_referers = (LENGTH(referer_array) - LENGTH(REPLACE(referer_array, ',', '')) + 1);
    
    -- Generate 30 time buckets (5-minute intervals)
    WHILE v_time_counter < 30 DO
        SET v_bucket_ts = DATE_FORMAT(NOW() - INTERVAL v_interval_minutes MINUTE, '%Y-%m-%d %H:%i:00');
        
        -- Insert 3-8 different referers per time bucket
        SET v_referer_counter = 1;
        WHILE v_referer_counter <= FLOOR(RAND() * 6) + 3 DO
            -- Get referer (cycling through the list with some randomness)
            SET current_referer = SUBSTRING_INDEX(
                SUBSTRING_INDEX(referer_array, ',', 
                    ((v_time_counter * 3 + v_referer_counter + FLOOR(RAND() * 5)) % total_referers) + 1
                ), 
                ',', 
                -1
            );
            
            -- Generate deterministic hash for this referer
            SET referer_hash = UNHEX(MD5(CONCAT(v_server_id, v_bucket_ts, current_referer)));
            
            INSERT INTO `referer_request_stats` (
                `server_id`, 
                `bucket_ts`, 
                `referer_hash`, 
                `request_referer`, 
                `request_count`
            ) VALUES (
                v_server_id,
                v_bucket_ts,
                referer_hash,
                current_referer,
                FLOOR(RAND() * 500) + 50  -- 50-550 requests per referer
            ) ON DUPLICATE KEY UPDATE 
                request_count = request_count + VALUES(request_count);
            
            SET v_referer_counter = v_referer_counter + 1;
        END WHILE;
        
        SET v_time_counter = v_time_counter + 1;
        SET v_interval_minutes = v_interval_minutes - 5;
    END WHILE;
    
    SELECT CONCAT('Generated referer stats for server_id: ', v_server_id, ' - ', 
                  (SELECT COUNT(*) FROM referer_request_stats WHERE server_id = v_server_id), 
                  ' records created') AS result;
END//
DELIMITER ;

-- Dumping structure for procedure cdnproxy.GenerateRefererStatsForAllServers
DROP PROCEDURE IF EXISTS `GenerateRefererStatsForAllServers`;
DELIMITER //
CREATE PROCEDURE `GenerateRefererStatsForAllServers`()
BEGIN
    DECLARE v_server_id BIGINT;
    DECLARE v_bucket_ts DATETIME;
    DECLARE v_time_counter INT;
    DECLARE v_referer_counter INT;
    DECLARE v_interval_minutes INT;
    DECLARE v_server_counter INT DEFAULT 0;
    DECLARE v_total_servers INT;
    DECLARE v_done INT DEFAULT FALSE;
    
    -- Popular referers categorized
    DECLARE search_engines TEXT DEFAULT 'https://www.google.com/,https://www.bing.com/,https://www.yahoo.com/,https://duckduckgo.com/,https://www.baidu.com/,https://www.yandex.ru/';
    DECLARE social_media TEXT DEFAULT 'https://www.facebook.com/,https://twitter.com/,https://www.linkedin.com/,https://www.reddit.com/,https://www.instagram.com/,https://www.pinterest.com/,https://www.tiktok.com/';
    DECLARE tech_sites TEXT DEFAULT 'https://github.com/,https://stackoverflow.com/,https://medium.com/,https://dev.to/,https://news.ycombinator.com/,https://gitlab.com/,https://bitbucket.org/';
    DECLARE misc TEXT DEFAULT 'direct,unknown,https://mail.google.com/,https://outlook.live.com/,https://www.amazon.com/,https://www.youtube.com/,https://www.twitch.tv/,https://discord.com/';
    
    DECLARE current_referer TEXT;
    DECLARE referer_hash BINARY(16);
    
    -- Get all server IDs
    DECLARE server_cursor CURSOR FOR SELECT id FROM servers;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;
    
    -- Get total servers
    SELECT COUNT(*) INTO v_total_servers FROM servers;
    
    OPEN server_cursor;
    
    server_loop: LOOP
        FETCH server_cursor INTO v_server_id;
        IF v_done THEN
            LEAVE server_loop;
        END IF;
        
        SET v_server_counter = v_server_counter + 1;
        SET v_time_counter = 0;
        SET v_interval_minutes = 145;
        
        -- Generate data for 30 time buckets per server
        WHILE v_time_counter < 30 DO
            SET v_bucket_ts = DATE_FORMAT(NOW() - INTERVAL v_interval_minutes MINUTE, '%Y-%m-%d %H:%i:00');
            
            -- Determine number of referers for this time bucket (varies by server/time)
            SET v_referer_counter = 0;
            
            -- Add search engines (usually 1-3 per bucket)
            WHILE v_referer_counter < FLOOR(RAND() * 3) + 1 DO
                SET current_referer = SUBSTRING_INDEX(
                    SUBSTRING_INDEX(search_engines, ',', 
                        (FLOOR(RAND() * 6) + 1)
                    ), 
                    ',', 
                    -1
                );
                
                SET referer_hash = UNHEX(MD5(CONCAT(v_server_id, v_bucket_ts, current_referer)));
                
                INSERT INTO `referer_request_stats` (
                    `server_id`, `bucket_ts`, `referer_hash`, `request_referer`, `request_count`
                ) VALUES (
                    v_server_id, v_bucket_ts, referer_hash, current_referer, 
                    FLOOR(RAND() * 400) + 100  -- 100-500 requests
                ) ON DUPLICATE KEY UPDATE request_count = request_count + VALUES(request_count);
                
                SET v_referer_counter = v_referer_counter + 1;
            END WHILE;
            
            -- Add social media (0-2 per bucket)
            SET v_referer_counter = 0;
            WHILE v_referer_counter < FLOOR(RAND() * 3) DO
                SET current_referer = SUBSTRING_INDEX(
                    SUBSTRING_INDEX(social_media, ',', 
                        (FLOOR(RAND() * 7) + 1)
                    ), 
                    ',', 
                    -1
                );
                
                SET referer_hash = UNHEX(MD5(CONCAT(v_server_id, v_bucket_ts, current_referer)));
                
                INSERT INTO `referer_request_stats` (
                    `server_id`, `bucket_ts`, `referer_hash`, `request_referer`, `request_count`
                ) VALUES (
                    v_server_id, v_bucket_ts, referer_hash, current_referer, 
                    FLOOR(RAND() * 300) + 50  -- 50-350 requests
                ) ON DUPLICATE KEY UPDATE request_count = request_count + VALUES(request_count);
                
                SET v_referer_counter = v_referer_counter + 1;
            END WHILE;
            
            -- Add tech sites (more likely during business hours)
            IF HOUR(v_bucket_ts) BETWEEN 9 AND 17 THEN
                SET v_referer_counter = 0;
                WHILE v_referer_counter < FLOOR(RAND() * 2) + 1 DO
                    SET current_referer = SUBSTRING_INDEX(
                        SUBSTRING_INDEX(tech_sites, ',', 
                            (FLOOR(RAND() * 7) + 1)
                        ), 
                        ',', 
                        -1
                    );
                    
                    SET referer_hash = UNHEX(MD5(CONCAT(v_server_id, v_bucket_ts, current_referer)));
                    
                    INSERT INTO `referer_request_stats` (
                        `server_id`, `bucket_ts`, `referer_hash`, `request_referer`, `request_count`
                    ) VALUES (
                        v_server_id, v_bucket_ts, referer_hash, current_referer, 
                        FLOOR(RAND() * 200) + 30  -- 30-230 requests
                    ) ON DUPLICATE KEY UPDATE request_count = request_count + VALUES(request_count);
                    
                    SET v_referer_counter = v_referer_counter + 1;
                END WHILE;
            END IF;
            
            -- Add misc referers including direct/unknown
            SET current_referer = CASE 
                WHEN RAND() < 0.3 THEN 'direct'
                WHEN RAND() < 0.5 THEN 'unknown'
                ELSE SUBSTRING_INDEX(
                    SUBSTRING_INDEX(misc, ',', 
                        (FLOOR(RAND() * 8) + 3)  -- Skip first two (direct, unknown)
                    ), 
                    ',', 
                    -1
                )
            END;
            
            SET referer_hash = UNHEX(MD5(CONCAT(v_server_id, v_bucket_ts, current_referer)));
            
            -- Direct/unknown tend to have more requests
            IF current_referer IN ('direct', 'unknown') THEN
                INSERT INTO `referer_request_stats` (
                    `server_id`, `bucket_ts`, `referer_hash`, `request_referer`, `request_count`
                ) VALUES (
                    v_server_id, v_bucket_ts, referer_hash, current_referer, 
                    FLOOR(RAND() * 800) + 200  -- 200-1000 requests
                ) ON DUPLICATE KEY UPDATE request_count = request_count + VALUES(request_count);
            ELSE
                INSERT INTO `referer_request_stats` (
                    `server_id`, `bucket_ts`, `referer_hash`, `request_referer`, `request_count`
                ) VALUES (
                    v_server_id, v_bucket_ts, referer_hash, current_referer, 
                    FLOOR(RAND() * 150) + 20  -- 20-170 requests
                ) ON DUPLICATE KEY UPDATE request_count = request_count + VALUES(request_count);
            END IF;
            
            SET v_time_counter = v_time_counter + 1;
            SET v_interval_minutes = v_interval_minutes - 5;
        END WHILE;
        
        -- Progress update every 5 servers
        IF v_server_counter % 5 = 0 THEN
            SELECT CONCAT('Processed ', v_server_counter, ' of ', v_total_servers, ' servers') AS progress;
        END IF;
    END LOOP;
    
    CLOSE server_cursor;
    
    SELECT CONCAT('Generated referer stats for ', v_server_counter, ' servers. Total records: ',
                  (SELECT COUNT(*) FROM referer_request_stats)) AS final_result;
END//
DELIMITER ;

-- Dumping structure for procedure cdnproxy.GenerateSafeSampleData
DROP PROCEDURE IF EXISTS `GenerateSafeSampleData`;
DELIMITER //
CREATE PROCEDURE `GenerateSafeSampleData`()
BEGIN
    DECLARE counter INT DEFAULT 0;
    DECLARE v_server_id BIGINT;
    
    -- Create temporary table of valid server IDs
    DROP TEMPORARY TABLE IF EXISTS temp_valid_servers;
    CREATE TEMPORARY TABLE temp_valid_servers (server_id BIGINT PRIMARY KEY);
    
    INSERT INTO temp_valid_servers (server_id) 
    SELECT id FROM servers;
    
    -- If no servers, insert some defaults
    IF (SELECT COUNT(*) FROM temp_valid_servers) = 0 THEN
        INSERT INTO servers (id, name) VALUES (1, 'Test Server'), (2, 'Backup Server');
        INSERT INTO temp_valid_servers (server_id) VALUES (1), (2);
    END IF;
    
    WHILE counter < 100 DO
        -- Get random valid server ID
        SELECT server_id INTO v_server_id 
        FROM temp_valid_servers 
        ORDER BY RAND() 
        LIMIT 1;
        
        -- Insert sample record (simplified)
        INSERT INTO ip_request_stats (server_id, bucket_ts, ip, request_count)
        VALUES (
            v_server_id,
            FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL FLOOR(RAND() * 2880) MINUTE)) / 900) * 900),
            INET6_ATON(CONCAT('192.168.', FLOOR(RAND() * 256), '.', FLOOR(1 + RAND() * 254))),
            FLOOR(1 + (RAND() * 100))
        )
        ON DUPLICATE KEY UPDATE request_count = VALUES(request_count);
        
        SET counter = counter + 1;
    END WHILE;
    
    DROP TEMPORARY TABLE temp_valid_servers;
    SELECT CONCAT('Inserted ', counter, ' records') AS result;
END//
DELIMITER ;

-- Dumping structure for procedure cdnproxy.GenerateTestTrafficStats
DROP PROCEDURE IF EXISTS `GenerateTestTrafficStats`;
DELIMITER //
CREATE PROCEDURE `GenerateTestTrafficStats`()
BEGIN
    DECLARE i INT DEFAULT 0;
    DECLARE interval_minutes INT DEFAULT 145;
    
    WHILE i < 30 DO
        INSERT INTO `server_traffic_stats` (
            `server_id`, `bucket_ts`, `traffic`, `bandwidth`, 
            `request_count`, `response_count`, `blocked_request_count`,
            `ip_count`, `blocked_ip_count`, `code200`, `code206`, 
            `code301`, `code302`, `code400`, `code403`, `code404`,
            `code444`, `code499`, `code500`, `code502`, `code503`,
            `code504`, `code904`, `code929`, `code978`, `get_count`,
            `post_count`, `delete_count`, `put_count`, `head_count`,
            `patch_count`, `options_count`, `others_count`,
            `http1_0_count`, `http1_1_count`, `http2_count`, `http3_count`
        ) VALUES (
            31, 
            NOW() - INTERVAL interval_minutes MINUTE,
            FLOOR(RAND() * 1000000), 
            FLOOR(RAND() * 100000),
            FLOOR(RAND() * 5000), 
            FLOOR(RAND() * 4500), 
            FLOOR(RAND() * 500),
            FLOOR(RAND() * 500), 
            FLOOR(RAND() * 50),
            FLOOR(RAND() * 3000), 
            FLOOR(RAND() * 200),
            FLOOR(RAND() * 50), 
            FLOOR(RAND() * 30),
            FLOOR(RAND() * 100), 
            FLOOR(RAND() * 80),
            FLOOR(RAND() * 150), 
            FLOOR(RAND() * 40),
            FLOOR(RAND() * 60), 
            FLOOR(RAND() * 30),
            FLOOR(RAND() * 20), 
            FLOOR(RAND() * 15),
            FLOOR(RAND() * 10), 
            FLOOR(RAND() * 8),
            FLOOR(RAND() * 5), 
            FLOOR(RAND() * 3),
            FLOOR(RAND() * 4000), 
            FLOOR(RAND() * 800),
            FLOOR(RAND() * 100), 
            FLOOR(RAND() * 150),
            FLOOR(RAND() * 80), 
            FLOOR(RAND() * 60),
            FLOOR(RAND() * 40), 
            FLOOR(RAND() * 200),
            FLOOR(RAND() * 100), 
            FLOOR(RAND() * 4500),
            FLOOR(RAND() * 200), 
            FLOOR(RAND() * 50)
        );
        
        SET i = i + 1;
        SET interval_minutes = interval_minutes - 5;
    END WHILE;
END//
DELIMITER ;

-- Dumping structure for procedure cdnproxy.GenerateUrlRequestStats
DROP PROCEDURE IF EXISTS `GenerateUrlRequestStats`;
DELIMITER //
CREATE PROCEDURE `GenerateUrlRequestStats`()
BEGIN
    DECLARE v_server_id BIGINT;
    DECLARE v_bucket_ts DATETIME;
    DECLARE v_url_index INT;
    DECLARE v_interval_minutes INT DEFAULT 145;
    DECLARE v_time_counter INT;
    DECLARE v_url_counter INT;
    DECLARE v_url_count INT;
    DECLARE v_done INT DEFAULT FALSE;
    
    -- Common URL paths for a CDN/proxy service
    DECLARE url_paths TEXT DEFAULT '/,/index.html,/api/v1/users,/api/v1/products,/api/v1/orders,/static/css/style.css,/static/js/app.js,/images/logo.png,/images/banner.jpg,/videos/intro.mp4,/downloads/software.zip,/blog,/blog/post-1,/blog/post-2,/contact,/about,/privacy,/terms,/login,/register,/dashboard,/profile,/settings,/api/v2/auth,/api/v2/data,/api/v2/config,/api/health,/api/metrics,/api/logs,/search,/sitemap.xml,/robots.txt,/favicon.ico,/manifest.json,/service-worker.js,/api/v3/cache,/api/v3/purge,/cdn/assets/img1.jpg,/cdn/assets/img2.png,/cdn/assets/video1.mp4,/cdn/scripts/main.js,/cdn/styles/theme.css';
    
    -- Domain variations
    DECLARE domains TEXT DEFAULT 'example.com,cdn.example.com,api.example.com,static.example.com,images.example.com,video.example.com,download.example.com,blog.example.com';
    
    -- URL query parameters
    DECLARE query_params TEXT DEFAULT '?cache=true&version=1,?width=1920&height=1080,?format=webp&quality=80,?token=abc123&expires=3600,?page=1&limit=50,?sort=date&order=desc,?filter=active&status=1,?search=test&q=query,?locale=en_US&region=us,?debug=true&trace=1';
    
    DECLARE current_path TEXT;
    DECLARE current_domain TEXT;
    DECLARE current_param TEXT;
    DECLARE full_url TEXT;
    DECLARE url_hash BINARY(16);
    
    -- Cursor for servers
    DECLARE v_server_cursor CURSOR FOR SELECT id FROM servers LIMIT 5;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;
    
    -- Calculate counts
    SET v_url_count = (LENGTH(url_paths) - LENGTH(REPLACE(url_paths, ',', '')) + 1);
    
    OPEN v_server_cursor;
    
    server_loop: LOOP
        FETCH v_server_cursor INTO v_server_id;
        IF v_done THEN
            LEAVE server_loop;
        END IF;
        
        -- Reset interval for each server
        SET v_interval_minutes = 145;
        SET v_time_counter = 0;
        
        -- Generate data for 30 time buckets (5-minute intervals)
        WHILE v_time_counter < 30 DO
            -- Calculate bucket time (going backwards)
            SET v_bucket_ts = NOW() - INTERVAL v_interval_minutes MINUTE;
            -- Round to nearest 5-minute bucket
            SET v_bucket_ts = FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(v_bucket_ts) / 300) * 300);
            
            -- Insert 3-8 different URLs per time bucket
            SET v_url_counter = 0;
            SET v_url_index = FLOOR(RAND() * (v_url_count - 5)) + 1;
            
            WHILE v_url_counter < FLOOR(RAND() * 6) + 3 DO
                -- Extract URL path
                SET current_path = SUBSTRING_INDEX(
                    SUBSTRING_INDEX(url_paths, ',', v_url_index), 
                    ',', 
                    -1
                );
                
                -- Select random domain
                SET current_domain = SUBSTRING_INDEX(
                    SUBSTRING_INDEX(domains, ',', FLOOR(RAND() * 8) + 1),
                    ',',
                    -1
                );
                
                -- Add query parameters 40% of the time
                IF RAND() < 0.4 THEN
                    SET current_param = SUBSTRING_INDEX(
                        SUBSTRING_INDEX(query_params, ',', FLOOR(RAND() * 10) + 1),
                        ',',
                        -1
                    );
                ELSE
                    SET current_param = '';
                END IF;
                
                -- Construct full URL
                SET full_url = CONCAT(
                    'https://',
                    current_domain,
                    current_path,
                    current_param
                );
                
                -- Generate deterministic hash
                SET url_hash = UNHEX(MD5(CONCAT(v_server_id, v_bucket_ts, full_url)));
                
                -- Insert record with realistic request count distribution
                INSERT INTO `url_request_stats` (
                    `server_id`, 
                    `bucket_ts`, 
                    `url_hash`, 
                    `request_url`, 
                    `request_count`
                ) VALUES (
                    v_server_id,
                    v_bucket_ts,
                    url_hash,
                    full_url,
                    CASE 
                        -- Homepage and static assets get highest traffic
                        WHEN current_path IN ('/', '/index.html') THEN FLOOR(RAND() * 5000) + 1000
                        -- API endpoints get medium traffic
                        WHEN current_path LIKE '/api/%' THEN FLOOR(RAND() * 1000) + 100
                        -- Static assets (CSS, JS, images)
                        WHEN current_path LIKE '%/static/%' OR current_path LIKE '%/images/%' OR current_path LIKE '%/cdn/%' THEN FLOOR(RAND() * 2000) + 500
                        -- Pages (blog, contact, about)
                        WHEN current_path LIKE '/blog%' OR current_path IN ('/contact', '/about', '/privacy', '/terms') THEN FLOOR(RAND() * 300) + 50
                        -- Auth and user pages
                        WHEN current_path IN ('/login', '/register', '/dashboard', '/profile', '/settings') THEN FLOOR(RAND() * 200) + 20
                        -- System files
                        WHEN current_path IN ('/robots.txt', '/sitemap.xml', '/favicon.ico', '/manifest.json') THEN FLOOR(RAND() * 100) + 10
                        -- Default
                        ELSE FLOOR(RAND() * 100) + 5
                    END
                ) ON DUPLICATE KEY UPDATE 
                    request_count = request_count + VALUES(request_count);
                
                SET v_url_counter = v_url_counter + 1;
                SET v_url_index = v_url_index + 1;
                
                -- Wrap around if we exceed the URL list
                IF v_url_index > v_url_count THEN
                    SET v_url_index = 1;
                END IF;
            END WHILE;
            
            SET v_time_counter = v_time_counter + 1;
            SET v_interval_minutes = v_interval_minutes - 5;
        END WHILE;
    END LOOP;
    
    CLOSE v_server_cursor;
    
    -- Return summary
    SELECT 
        CONCAT('Generated URL request data for ', 
               (SELECT COUNT(DISTINCT server_id) FROM url_request_stats WHERE bucket_ts >= NOW() - INTERVAL 150 MINUTE),
               ' servers') AS result;
END//
DELIMITER ;

-- Dumping structure for procedure cdnproxy.GenerateUserAgentStats
DROP PROCEDURE IF EXISTS `GenerateUserAgentStats`;
DELIMITER //
CREATE PROCEDURE `GenerateUserAgentStats`()
BEGIN
    DECLARE v_server_id BIGINT;
    DECLARE v_bucket_ts DATETIME;
    DECLARE v_ua_index INT;
    DECLARE v_interval_minutes INT DEFAULT 145;
    DECLARE v_time_counter INT;
    DECLARE v_ua_counter INT;
    DECLARE v_ua_count INT;
    DECLARE v_done INT DEFAULT FALSE;
    
    -- Common user agents list
    DECLARE useragents TEXT DEFAULT 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36,Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0,Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0,Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15,Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1,Mozilla/5.0 (Linux; Android 14; SM-S901U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36,Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36,Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html),Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm),Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36,Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1,curl/7.88.1,PostmanRuntime/7.36.0';
    
    DECLARE current_ua TEXT;
    DECLARE ua_hash BINARY(16);
    
    -- Cursor for servers
    DECLARE v_server_cursor CURSOR FOR SELECT id FROM servers LIMIT 5;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;
    
    -- Calculate user agent count
    SET v_ua_count = (LENGTH(useragents) - LENGTH(REPLACE(useragents, ',', '')) + 1);
    
    OPEN v_server_cursor;
    
    server_loop: LOOP
        FETCH v_server_cursor INTO v_server_id;
        IF v_done THEN
            LEAVE server_loop;
        END IF;
        
        -- Reset interval for each server (go back 145 minutes initially)
        SET v_interval_minutes = 145;
        SET v_time_counter = 0;
        
        -- Generate data for 30 time buckets (5-minute intervals covering ~2.5 hours)
        WHILE v_time_counter < 30 DO
            -- Calculate bucket time (going backwards in time)
            SET v_bucket_ts = NOW() - INTERVAL v_interval_minutes MINUTE;
            -- Round to nearest 5-minute bucket
            SET v_bucket_ts = FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(v_bucket_ts) / 300) * 300);
            
            -- Insert 2-5 different user agents per time bucket
            SET v_ua_counter = 0;
            -- Start from random position in UA list
            SET v_ua_index = FLOOR(RAND() * (v_ua_count - 2)) + 1;
            
            WHILE v_ua_counter < FLOOR(RAND() * 4) + 2 DO
                -- Extract user agent from comma-separated list
                SET current_ua = SUBSTRING_INDEX(
                    SUBSTRING_INDEX(useragents, ',', v_ua_index), 
                    ',', 
                    -1
                );
                
                -- Generate deterministic hash for this user agent
                SET ua_hash = UNHEX(MD5(CONCAT(v_server_id, v_bucket_ts, current_ua)));
                
                -- Insert record
                INSERT INTO `useragent_request_stats` (
                    `server_id`, 
                    `bucket_ts`, 
                    `useragent_hash`, 
                    `request_useragent`, 
                    `request_count`
                ) VALUES (
                    v_server_id,
                    v_bucket_ts,
                    ua_hash,
                    current_ua,
                    -- Generate request count with realistic distribution
                    CASE 
                        WHEN current_ua LIKE '%bot%' THEN FLOOR(RAND() * 10) + 1      -- Bots: 1-10 requests
                        WHEN current_ua LIKE '%Mobile%' THEN FLOOR(RAND() * 100) + 10  -- Mobile: 10-110 requests
                        WHEN current_ua LIKE '%curl%' OR current_ua LIKE '%Postman%' THEN FLOOR(RAND() * 5) + 1  -- Tools: 1-5 requests
                        ELSE FLOOR(RAND() * 500) + 50                                 -- Desktop browsers: 50-550 requests
                    END
                ) ON DUPLICATE KEY UPDATE 
                    request_count = request_count + VALUES(request_count);
                
                SET v_ua_counter = v_ua_counter + 1;
                SET v_ua_index = v_ua_index + 1;
                
                -- Wrap around if we exceed the UA list
                IF v_ua_index > v_ua_count THEN
                    SET v_ua_index = 1;
                END IF;
            END WHILE;
            
            SET v_time_counter = v_time_counter + 1;
            SET v_interval_minutes = v_interval_minutes - 5;  -- Move to next 5-minute bucket
        END WHILE;
    END LOOP;
    
    CLOSE v_server_cursor;
    
    -- Return summary
    SELECT 
        CONCAT('Generated user agent data for ', 
               (SELECT COUNT(DISTINCT server_id) FROM useragent_request_stats WHERE bucket_ts >= NOW() - INTERVAL 150 MINUTE),
               ' servers') AS result;
END//
DELIMITER ;

-- Dumping structure for function cdnproxy.get_server_with_defense
DROP FUNCTION IF EXISTS `get_server_with_defense`;
DELIMITER //
CREATE FUNCTION `get_server_with_defense`(p_server_id INT) RETURNS json
    READS SQL DATA
    DETERMINISTIC
BEGIN
    DECLARE result JSON;
    
    SELECT JSON_OBJECT(
        'server', JSON_OBJECT(
            'id', s.id,
            'name', s.name,
            'ip', s.ip,
            'l4_id', s.l4_id
        ),
        'ddos_defense', JSON_OBJECT(
            'id', d.id,
            'global', JSON_OBJECT(
                'dev', d.dev,
                'attach_mode', d.attach_mode,
                'black_ip_duration', d.black_ip_duration
            ),
            'syn_protection', JSON_OBJECT(
                'valid', d.syn_valid,
                'threshold', d.syn_threshold,
                'burst_pkt', d.syn_burst_pkt,
                'burst_count_per_sec', d.syn_burst_count_per_sec,
                'fixed_threshold', d.syn_fixed_threshold,
                'fixed_check_duration', d.syn_fixed_check_duration,
                'challenge_timeout', d.challenge_timeout,
                'protection_duration', d.syn_protection_duration
            ),
            'ack_protection', JSON_OBJECT(
                'valid', d.ack_valid,
                'threshold', d.ack_threshold,
                'burst_pkt', d.ack_burst_pkt,
                'burst_count_per_sec', d.ack_burst_count_per_sec,
                'fixed_threshold', d.ack_fixed_threshold,
                'fixed_check_duration', d.ack_fixed_check_duration,
                'protection_duration', d.ack_protection_duration
            )
            -- Add other sections similarly...
        )
    ) INTO result
    FROM servers s
    LEFT JOIN l4_ddos_defense d ON s.l4_id = d.id
    WHERE s.id = p_server_id;
    
    RETURN result;
END//
DELIMITER ;

-- Dumping structure for table cdnproxy.ip_request_stats
DROP TABLE IF EXISTS `ip_request_stats`;
CREATE TABLE IF NOT EXISTS `ip_request_stats` (
  `server_id` bigint NOT NULL,
  `bucket_ts` datetime NOT NULL,
  `ip` varbinary(16) NOT NULL,
  `request_count` int unsigned NOT NULL DEFAULT '1',
  PRIMARY KEY (`server_id`,`bucket_ts`,`ip`),
  KEY `idx_bucket` (`bucket_ts`),
  KEY `idx_ip` (`ip`),
  KEY `idx_server_bucket` (`server_id`,`bucket_ts`),
  CONSTRAINT `ip_request_stats_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.isp_request_stats
DROP TABLE IF EXISTS `isp_request_stats`;
CREATE TABLE IF NOT EXISTS `isp_request_stats` (
  `server_id` bigint NOT NULL,
  `bucket_ts` datetime NOT NULL,
  `isp_hash` binary(16) NOT NULL,
  `request_isp` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `request_count` int unsigned NOT NULL DEFAULT '1',
  PRIMARY KEY (`server_id`,`bucket_ts`,`isp_hash`) USING BTREE,
  KEY `idx_bucket` (`bucket_ts`) USING BTREE,
  KEY `idx_server_bucket` (`server_id`,`bucket_ts`) USING BTREE,
  CONSTRAINT `isp_request_stats_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.l4_attack_stats
DROP TABLE IF EXISTS `l4_attack_stats`;
CREATE TABLE IF NOT EXISTS `l4_attack_stats` (
  `server_id` bigint NOT NULL,
  `bucket_ts` datetime NOT NULL,
  `total_traffic` bigint unsigned NOT NULL DEFAULT '0',
  `allowed_traffic` bigint unsigned NOT NULL DEFAULT '0',
  `blocked_traffic` bigint unsigned NOT NULL DEFAULT '0',
  `tcp` bigint unsigned NOT NULL DEFAULT '0',
  `udp` bigint unsigned NOT NULL DEFAULT '0',
  `icmp` bigint unsigned NOT NULL DEFAULT '0',
  `gre` bigint unsigned NOT NULL DEFAULT '0',
  `other` bigint unsigned NOT NULL DEFAULT '0',
  `tcp_syn` bigint unsigned NOT NULL DEFAULT '0',
  `tcp_ack` bigint unsigned NOT NULL DEFAULT '0',
  `tcp_rst` bigint unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`server_id`,`bucket_ts`),
  KEY `idx_bucket` (`bucket_ts`),
  CONSTRAINT `l4_attack_stats_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.l4_blacklist
DROP TABLE IF EXISTS `l4_blacklist`;
CREATE TABLE IF NOT EXISTS `l4_blacklist` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `source_ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `reason` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `l4_blacklist_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1056 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.l4_ddos_defense
DROP TABLE IF EXISTS `l4_ddos_defense`;
CREATE TABLE IF NOT EXISTS `l4_ddos_defense` (
  `id` int NOT NULL AUTO_INCREMENT,
  `dev` varchar(50) DEFAULT 'eth2',
  `protection_mode` enum('Always On','Monitor') DEFAULT 'Always On',
  `sensitivity` enum('Low','Medium','High') DEFAULT 'Medium',
  `attach_mode` enum('skb','native','drv','hw') DEFAULT 'native',
  `black_ip_duration` int DEFAULT '3600',
  `syn_valid` tinyint(1) DEFAULT '1',
  `syn_threshold` int DEFAULT '200000',
  `syn_burst_pkt` int DEFAULT '20',
  `syn_burst_count_per_sec` int DEFAULT '10',
  `syn_fixed_threshold` int DEFAULT '2000',
  `syn_fixed_check_duration` int DEFAULT '15',
  `challenge_timeout` int DEFAULT '3',
  `syn_protection_duration` int DEFAULT '60',
  `ack_valid` tinyint(1) DEFAULT '1',
  `ack_threshold` int DEFAULT '200000',
  `ack_burst_pkt` int DEFAULT '200',
  `ack_burst_count_per_sec` int DEFAULT '100',
  `ack_fixed_threshold` int DEFAULT '2000',
  `ack_fixed_check_duration` int DEFAULT '15',
  `ack_protection_duration` int DEFAULT '60',
  `rst_valid` tinyint(1) DEFAULT '1',
  `rst_threshold` int DEFAULT '200000',
  `rst_burst_pkt` int DEFAULT '20',
  `rst_burst_count_per_sec` int DEFAULT '10',
  `rst_fixed_threshold` int DEFAULT '2000',
  `rst_fixed_check_duration` int DEFAULT '15',
  `rst_protection_duration` int DEFAULT '60',
  `icmp_valid` tinyint(1) DEFAULT '1',
  `icmp_threshold` int DEFAULT '200000',
  `icmp_burst_pkt` int DEFAULT '20',
  `icmp_burst_count_per_sec` int DEFAULT '10',
  `icmp_fixed_threshold` int DEFAULT '2000',
  `icmp_fixed_check_duration` int DEFAULT '15',
  `icmp_protection_duration` int DEFAULT '60',
  `udp_valid` tinyint(1) DEFAULT '1',
  `udp_threshold` int DEFAULT '200000',
  `udp_burst_pkt` int DEFAULT '20',
  `udp_burst_count_per_sec` int DEFAULT '10',
  `udp_fixed_threshold` int DEFAULT '2000',
  `udp_fixed_check_duration` int DEFAULT '15',
  `udp_protection_duration` int DEFAULT '60',
  `gre_valid` tinyint(1) DEFAULT '1',
  `gre_threshold` int DEFAULT '200000',
  `gre_burst_pkt` int DEFAULT '20',
  `gre_burst_count_per_sec` int DEFAULT '10',
  `gre_fixed_threshold` int DEFAULT '2000',
  `gre_fixed_check_duration` int DEFAULT '15',
  `gre_protection_duration` int DEFAULT '60',
  `tcp_seg_check` tinyint(1) DEFAULT '0',
  `geo_check` tinyint(1) DEFAULT '0',
  `geo_db_ipv4_path` varchar(255) DEFAULT 'geodb/ipv4.csv',
  `geo_db_location_path` varchar(255) DEFAULT 'geodb/location.csv',
  `geo_allow_countries` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `tcp_connection_limit_check` tinyint(1) DEFAULT '1',
  `tcp_connection_limit_cnt` int DEFAULT '50',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1137 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.l4_live_attack
DROP TABLE IF EXISTS `l4_live_attack`;
CREATE TABLE IF NOT EXISTS `l4_live_attack` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `source_ip` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `attack_type` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `l4_live_attack_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1070 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.l4_whitelist
DROP TABLE IF EXISTS `l4_whitelist`;
CREATE TABLE IF NOT EXISTS `l4_whitelist` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `source_ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `reason` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `l4_whitelist_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1055 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.referer_request_stats
DROP TABLE IF EXISTS `referer_request_stats`;
CREATE TABLE IF NOT EXISTS `referer_request_stats` (
  `server_id` bigint NOT NULL,
  `bucket_ts` datetime NOT NULL,
  `referer_hash` binary(16) NOT NULL,
  `request_referer` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `request_count` int unsigned NOT NULL DEFAULT '1',
  PRIMARY KEY (`server_id`,`bucket_ts`,`referer_hash`) USING BTREE,
  KEY `idx_bucket` (`bucket_ts`) USING BTREE,
  KEY `idx_server_bucket` (`server_id`,`bucket_ts`) USING BTREE,
  CONSTRAINT `referer_request_stats_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.security_events
DROP TABLE IF EXISTS `security_events`;
CREATE TABLE IF NOT EXISTS `security_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `title` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=1021 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.servers
DROP TABLE IF EXISTS `servers`;
CREATE TABLE IF NOT EXISTS `servers` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `status` enum('Normal','Pause','Expired') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'Normal',
  `license_type` enum('Enterprise','Professional','Trial') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'Trial',
  `license_file` varchar(1024) DEFAULT NULL,
  `version` varchar(50) DEFAULT NULL,
  `created` datetime DEFAULT NULL,
  `expired` datetime DEFAULT NULL,
  `ssh_user` varchar(64) DEFAULT NULL,
  `ssh_password` varchar(255) DEFAULT NULL,
  `ssh_port` int DEFAULT '22',
  `l4_id` int DEFAULT NULL,
  `token` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `id` (`id`),
  KEY `idx_servers_l4_id` (`l4_id`),
  CONSTRAINT `fk_server_l4_defense` FOREIGN KEY (`l4_id`) REFERENCES `l4_ddos_defense` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=1033 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.server_traffic_stats
DROP TABLE IF EXISTS `server_traffic_stats`;
CREATE TABLE IF NOT EXISTS `server_traffic_stats` (
  `server_id` bigint NOT NULL,
  `bucket_ts` datetime NOT NULL,
  `traffic_nic_rx` float unsigned NOT NULL DEFAULT (0),
  `traffic_nic_tx` float unsigned NOT NULL DEFAULT (0),
  `traffic_l7_rx` float unsigned NOT NULL DEFAULT (0),
  `traffic_l7_tx` float unsigned NOT NULL DEFAULT (0),
  `bandwidth_nic_rx` bigint unsigned NOT NULL DEFAULT '0',
  `bandwidth_nic_tx` bigint unsigned NOT NULL DEFAULT '0',
  `bandwidth_l7_rx` bigint unsigned NOT NULL DEFAULT '0',
  `bandwidth_l7_tx` bigint unsigned NOT NULL DEFAULT '0',
  `request_count` bigint unsigned NOT NULL DEFAULT '0',
  `response_count` bigint unsigned NOT NULL DEFAULT '0',
  `blocked_request_count` bigint unsigned NOT NULL DEFAULT '0',
  `ip_count` int unsigned NOT NULL DEFAULT '0',
  `blocked_ip_count` int unsigned NOT NULL DEFAULT '0',
  `code200` bigint unsigned NOT NULL DEFAULT '0',
  `code206` bigint unsigned NOT NULL DEFAULT '0',
  `code301` bigint unsigned NOT NULL DEFAULT '0',
  `code302` bigint unsigned NOT NULL DEFAULT '0',
  `code400` bigint unsigned NOT NULL DEFAULT '0',
  `code403` bigint unsigned NOT NULL DEFAULT '0',
  `code404` bigint unsigned NOT NULL DEFAULT '0',
  `code444` bigint unsigned NOT NULL DEFAULT '0',
  `code499` bigint unsigned NOT NULL DEFAULT '0',
  `code500` bigint unsigned NOT NULL DEFAULT '0',
  `code502` bigint unsigned NOT NULL DEFAULT '0',
  `code503` bigint unsigned NOT NULL DEFAULT '0',
  `code504` bigint unsigned NOT NULL DEFAULT '0',
  `code904` bigint unsigned NOT NULL DEFAULT '0',
  `code929` bigint unsigned NOT NULL DEFAULT '0',
  `code978` bigint unsigned NOT NULL DEFAULT '0',
  `get_count` bigint unsigned NOT NULL DEFAULT '0',
  `post_count` bigint unsigned NOT NULL DEFAULT '0',
  `delete_count` bigint unsigned NOT NULL DEFAULT '0',
  `put_count` bigint unsigned NOT NULL DEFAULT '0',
  `head_count` bigint unsigned NOT NULL DEFAULT '0',
  `patch_count` bigint unsigned NOT NULL DEFAULT '0',
  `options_count` bigint unsigned NOT NULL DEFAULT '0',
  `others_count` bigint unsigned NOT NULL DEFAULT '0',
  `http1_0_count` bigint unsigned NOT NULL DEFAULT '0',
  `http1_1_count` bigint unsigned NOT NULL DEFAULT '0',
  `http2_count` bigint unsigned NOT NULL DEFAULT '0',
  `http3_count` bigint unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`server_id`,`bucket_ts`),
  KEY `idx_bucket` (`bucket_ts`),
  CONSTRAINT `server_traffic_stats_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.server_users
DROP TABLE IF EXISTS `server_users`;
CREATE TABLE IF NOT EXISTS `server_users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `user_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_membership` (`server_id`,`user_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `server_users_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE,
  CONSTRAINT `server_users_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1074 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for procedure cdnproxy.SP_GENERATE_L4_ATTACK_STATS
DROP PROCEDURE IF EXISTS `SP_GENERATE_L4_ATTACK_STATS`;
DELIMITER //
CREATE PROCEDURE `SP_GENERATE_L4_ATTACK_STATS`()
BEGIN
    DECLARE v_server_id BIGINT;
    DECLARE v_bucket_ts DATETIME;
    DECLARE v_interval_minutes INT DEFAULT 145;
    DECLARE v_time_counter INT;
    DECLARE v_done INT DEFAULT FALSE;
    
    -- Traffic patterns for different times
    DECLARE v_base_traffic BIGINT UNSIGNED;
    DECLARE v_attack_factor DECIMAL(5,2);
    DECLARE v_block_rate DECIMAL(5,2);
    
    -- Protocol distributions
    DECLARE v_tcp_ratio DECIMAL(5,4);
    DECLARE v_udp_ratio DECIMAL(5,4);
    DECLARE v_icmp_ratio DECIMAL(5,4);
    DECLARE v_gre_ratio DECIMAL(5,4);
    DECLARE v_other_ratio DECIMAL(5,4);
    
    -- TCP flag distributions
    DECLARE v_tcp_syn_ratio DECIMAL(5,4);
    DECLARE v_tcp_ack_ratio DECIMAL(5,4);
    DECLARE v_tcp_rst_ratio DECIMAL(5,4);
    
    -- Calculated values
    DECLARE v_total_traffic BIGINT UNSIGNED;
    DECLARE v_allowed_traffic BIGINT UNSIGNED;
    DECLARE v_blocked_traffic BIGINT UNSIGNED;
    DECLARE v_tcp_traffic BIGINT UNSIGNED;
    DECLARE v_udp_traffic BIGINT UNSIGNED;
    DECLARE v_icmp_traffic BIGINT UNSIGNED;
    DECLARE v_gre_traffic BIGINT UNSIGNED;
    DECLARE v_other_traffic BIGINT UNSIGNED;
    DECLARE v_tcp_syn_traffic BIGINT UNSIGNED;
    DECLARE v_tcp_ack_traffic BIGINT UNSIGNED;
    DECLARE v_tcp_rst_traffic BIGINT UNSIGNED;
    
    -- Cursor for servers
    DECLARE v_server_cursor CURSOR FOR SELECT id FROM servers LIMIT 5;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;
    
    OPEN v_server_cursor;
    
    server_loop: LOOP
        FETCH v_server_cursor INTO v_server_id;
        IF v_done THEN
            LEAVE server_loop;
        END IF;
        
        -- Reset interval for each server
        SET v_interval_minutes = 145;
        SET v_time_counter = 0;
        
        -- Generate data for 30 time buckets (5-minute intervals over ~2.5 hours)
        WHILE v_time_counter < 30 DO
            -- Calculate bucket time (going backwards)
            SET v_bucket_ts = NOW() - INTERVAL v_interval_minutes MINUTE;
            SET v_bucket_ts = FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(v_bucket_ts) / 300) * 300);
            
            -- Determine traffic patterns based on time and server
            SET @hour = HOUR(v_bucket_ts);
            SET @minute = MINUTE(v_bucket_ts);
            SET @server_mod = MOD(v_server_id, 3);
            
            -- Base traffic varies by time of day (in bytes)
            -- Reduced to smaller values to avoid overflow
            SET v_base_traffic = CASE 
                WHEN @hour BETWEEN 0 AND 5 THEN 50000000    -- 50 MB overnight
                WHEN @hour BETWEEN 6 AND 9 THEN 150000000   -- 150 MB morning rush
                WHEN @hour BETWEEN 10 AND 17 THEN 200000000 -- 200 MB daytime peak
                WHEN @hour BETWEEN 18 AND 21 THEN 250000000 -- 250 MB evening peak
                ELSE 100000000                              -- 100 MB late night
            END;
            
            -- Attack factor (0.1 to 3.0) - higher during certain times
            SET v_attack_factor = CASE 
                WHEN @hour BETWEEN 2 AND 4 THEN 0.5 + (RAND() * 1.0)   -- Low attack period
                WHEN @hour BETWEEN 9 AND 11 THEN 1.5 + (RAND() * 1.5)  -- Morning attacks
                WHEN @hour BETWEEN 14 AND 16 THEN 2.0 + (RAND() * 1.0) -- Afternoon DDoS
                WHEN @hour BETWEEN 19 AND 21 THEN 1.8 + (RAND() * 1.2) -- Evening attacks
                ELSE 0.8 + (RAND() * 0.7)                             -- Normal periods
            END;
            
            -- Block rate varies by server and time (0.01 to 0.30)
            SET v_block_rate = 0.05 + (@server_mod * 0.08) + (RAND() * 0.12);
            SET v_block_rate = LEAST(GREATEST(v_block_rate, 0.01), 0.30);
            
            -- Protocol distribution (sums to 1.0)
            SET v_tcp_ratio = 0.65 + (RAND() * 0.20);   -- 65-85% TCP
            SET v_udp_ratio = 0.10 + (RAND() * 0.15);   -- 10-25% UDP
            SET v_icmp_ratio = 0.02 + (RAND() * 0.03);  -- 2-5% ICMP
            SET v_gre_ratio = 0.01 + (RAND() * 0.02);   -- 1-3% GRE
            
            -- Calculate other ratio ensuring it doesn't go negative
            SET v_other_ratio = GREATEST(0, 1.0 - (v_tcp_ratio + v_udp_ratio + v_icmp_ratio + v_gre_ratio));
            
            -- Normalize ratios to ensure they sum to 1.0
            SET @sum_ratios = v_tcp_ratio + v_udp_ratio + v_icmp_ratio + v_gre_ratio + v_other_ratio;
            SET v_tcp_ratio = v_tcp_ratio / @sum_ratios;
            SET v_udp_ratio = v_udp_ratio / @sum_ratios;
            SET v_icmp_ratio = v_icmp_ratio / @sum_ratios;
            SET v_gre_ratio = v_gre_ratio / @sum_ratios;
            SET v_other_ratio = v_other_ratio / @sum_ratios;
            
            -- TCP flag distribution (within TCP traffic)
            SET v_tcp_syn_ratio = 0.40 + (RAND() * 0.30);  -- 40-70% SYN
            SET v_tcp_ack_ratio = 0.20 + (RAND() * 0.20);  -- 20-40% ACK
            SET v_tcp_rst_ratio = 0.05 + (RAND() * 0.10);  -- 5-15% RST
            
            -- Normalize TCP flag ratios
            SET @sum_tcp_ratios = v_tcp_syn_ratio + v_tcp_ack_ratio + v_tcp_rst_ratio;
            IF @sum_tcp_ratios > 1.0 THEN
                SET v_tcp_syn_ratio = v_tcp_syn_ratio / @sum_tcp_ratios;
                SET v_tcp_ack_ratio = v_tcp_ack_ratio / @sum_tcp_ratios;
                SET v_tcp_rst_ratio = v_tcp_rst_ratio / @sum_tcp_ratios;
            END IF;
            
            -- Calculate total traffic with attack factor
            SET v_total_traffic = FLOOR(v_base_traffic * v_attack_factor * (0.9 + RAND() * 0.2));
            
            -- Calculate blocked traffic (ensure it's less than total)
            SET v_blocked_traffic = FLOOR(v_total_traffic * v_block_rate * (0.8 + RAND() * 0.4));
            SET v_blocked_traffic = LEAST(v_total_traffic - 1, v_blocked_traffic);
            SET v_allowed_traffic = v_total_traffic - v_blocked_traffic;
            
            -- Calculate protocol-specific traffic
            SET v_tcp_traffic = FLOOR(v_total_traffic * v_tcp_ratio);
            SET v_udp_traffic = FLOOR(v_total_traffic * v_udp_ratio);
            SET v_icmp_traffic = FLOOR(v_total_traffic * v_icmp_ratio);
            SET v_gre_traffic = FLOOR(v_total_traffic * v_gre_ratio);
            
            -- Calculate other traffic as remainder
            SET v_other_traffic = v_total_traffic - (v_tcp_traffic + v_udp_traffic + v_icmp_traffic + v_gre_traffic);
            
            -- Ensure v_other_traffic is not negative
            IF v_other_traffic < 0 THEN
                -- Adjust by reducing from largest protocol
                SET v_tcp_traffic = v_tcp_traffic + v_other_traffic;
                SET v_other_traffic = 0;
            END IF;
            
            -- Calculate TCP flag traffic (within TCP traffic)
            SET v_tcp_syn_traffic = FLOOR(v_tcp_traffic * v_tcp_syn_ratio);
            SET v_tcp_ack_traffic = FLOOR(v_tcp_traffic * v_tcp_ack_ratio);
            SET v_tcp_rst_traffic = FLOOR(v_tcp_traffic * v_tcp_rst_ratio);
            
            -- Ensure TCP flag traffic doesn't exceed TCP traffic
            SET @tcp_flags_sum = v_tcp_syn_traffic + v_tcp_ack_traffic + v_tcp_rst_traffic;
            IF @tcp_flags_sum > v_tcp_traffic THEN
                SET v_tcp_syn_traffic = FLOOR(v_tcp_syn_traffic * v_tcp_traffic / @tcp_flags_sum);
                SET v_tcp_ack_traffic = FLOOR(v_tcp_ack_traffic * v_tcp_traffic / @tcp_flags_sum);
                SET v_tcp_rst_traffic = v_tcp_traffic - v_tcp_syn_traffic - v_tcp_ack_traffic;
            END IF;
            
            -- Insert record
            INSERT INTO `l4_attack_stats` (
                `server_id`, 
                `bucket_ts`, 
                `total_traffic`, 
                `allowed_traffic`, 
                `blocked_traffic`,
                `tcp`, 
                `udp`, 
                `icmp`, 
                `gre`, 
                `other`,
                `tcp_syn`, 
                `tcp_ack`, 
                `tcp_rst`
            ) VALUES (
                v_server_id,
                v_bucket_ts,
                v_total_traffic,
                v_allowed_traffic,
                v_blocked_traffic,
                v_tcp_traffic,
                v_udp_traffic,
                v_icmp_traffic,
                v_gre_traffic,
                v_other_traffic,
                v_tcp_syn_traffic,
                v_tcp_ack_traffic,
                v_tcp_rst_traffic
            ) ON DUPLICATE KEY UPDATE 
                total_traffic = VALUES(total_traffic),
                allowed_traffic = VALUES(allowed_traffic),
                blocked_traffic = VALUES(blocked_traffic),
                tcp = VALUES(tcp),
                udp = VALUES(udp),
                icmp = VALUES(icmp),
                gre = VALUES(gre),
                other = VALUES(other),
                tcp_syn = VALUES(tcp_syn),
                tcp_ack = VALUES(tcp_ack),
                tcp_rst = VALUES(tcp_rst);
            
            SET v_time_counter = v_time_counter + 1;
            SET v_interval_minutes = v_interval_minutes - 5;
        END WHILE;
    END LOOP;
    
    CLOSE v_server_cursor;
    
    -- Return summary
    SELECT 
        CONCAT('Generated L4 attack stats for ', 
               (SELECT COUNT(DISTINCT server_id) FROM l4_attack_stats WHERE bucket_ts >= NOW() - INTERVAL 150 MINUTE),
               ' servers') AS RESULT;
END//
DELIMITER ;

-- Dumping structure for table cdnproxy.upstream_servers
DROP TABLE IF EXISTS `upstream_servers`;
CREATE TABLE IF NOT EXISTS `upstream_servers` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `ip_port` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(500) NOT NULL DEFAULT '0',
  `status` enum('ENABLE','DISABLE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ENABLE',
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `upstream_servers_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1018 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.url_request_stats
DROP TABLE IF EXISTS `url_request_stats`;
CREATE TABLE IF NOT EXISTS `url_request_stats` (
  `server_id` bigint NOT NULL,
  `bucket_ts` datetime NOT NULL,
  `url_hash` binary(16) NOT NULL,
  `request_url` text NOT NULL,
  `request_count` int unsigned NOT NULL DEFAULT '1',
  PRIMARY KEY (`server_id`,`bucket_ts`,`url_hash`),
  KEY `idx_bucket` (`bucket_ts`),
  KEY `idx_server_bucket` (`server_id`,`bucket_ts`),
  CONSTRAINT `url_request_stats_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.useragent_request_stats
DROP TABLE IF EXISTS `useragent_request_stats`;
CREATE TABLE IF NOT EXISTS `useragent_request_stats` (
  `server_id` bigint NOT NULL,
  `bucket_ts` datetime NOT NULL,
  `useragent_hash` binary(16) NOT NULL,
  `request_useragent` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `request_count` int unsigned NOT NULL DEFAULT '1',
  PRIMARY KEY (`server_id`,`bucket_ts`,`useragent_hash`) USING BTREE,
  KEY `idx_bucket` (`bucket_ts`) USING BTREE,
  KEY `idx_server_bucket` (`server_id`,`bucket_ts`) USING BTREE,
  CONSTRAINT `useragent_request_stats_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.users
DROP TABLE IF EXISTS `users`;
CREATE TABLE IF NOT EXISTS `users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `role` enum('Admin','User') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `status` enum('Waiting','Active','Block') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `created` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=1007 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.waf_anticc
DROP TABLE IF EXISTS `waf_anticc`;
CREATE TABLE IF NOT EXISTS `waf_anticc` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `url` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `method` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  `threshold` int DEFAULT NULL,
  `window` int DEFAULT NULL,
  `action` enum('5-Second Shield','Challenge','Return Code') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `behavior` enum('Deny','Drop','Drop+Block') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'Drop',
  `status` enum('ENABLE','DISABLE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ENABLE',
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `waf_anticc_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1006 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.waf_antiheader
DROP TABLE IF EXISTS `waf_antiheader`;
CREATE TABLE IF NOT EXISTS `waf_antiheader` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `url` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `header` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `value` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `block_mode` enum('If match','If not match') DEFAULT NULL,
  `behavior` enum('Deny','Drop','Drop+Block') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'Drop',
  `status` enum('ENABLE','DISABLE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ENABLE',
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `waf_antiheader_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1008 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.waf_blacklist
DROP TABLE IF EXISTS `waf_blacklist`;
CREATE TABLE IF NOT EXISTS `waf_blacklist` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `black_ip_list` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `url` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `method` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `behavior` enum('Deny','Drop','Drop+Block') NOT NULL DEFAULT 'Drop',
  `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `waf_blacklist_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1029 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.waf_geolocation
DROP TABLE IF EXISTS `waf_geolocation`;
CREATE TABLE IF NOT EXISTS `waf_geolocation` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `country` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `url` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `behavior` enum('Deny','Drop','Drop+Block') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'Drop',
  `created_at` timestamp NULL DEFAULT (now()),
  `operation` enum('BLACK','WHITE') DEFAULT 'BLACK',
  `status` enum('ENABLE','DISABLE') DEFAULT 'ENABLE',
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `waf_geolocation_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1008 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.waf_intervalfreqlimit
DROP TABLE IF EXISTS `waf_intervalfreqlimit`;
CREATE TABLE IF NOT EXISTS `waf_intervalfreqlimit` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `url` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `time` int NOT NULL DEFAULT (0),
  `request_count` int NOT NULL DEFAULT (0),
  `behavior` enum('Deny','Drop','Drop+Block') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'Drop',
  `status` enum('ENABLE','DISABLE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ENABLE',
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `waf_intervalfreqlimit_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1008 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.waf_responsefreq
DROP TABLE IF EXISTS `waf_responsefreq`;
CREATE TABLE IF NOT EXISTS `waf_responsefreq` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `url` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `response_code` varchar(100) NOT NULL DEFAULT '0',
  `time` int NOT NULL DEFAULT '0',
  `response_count` int DEFAULT NULL,
  `behavior` enum('Deny','Drop','Drop+Block') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'Drop',
  `status` enum('ENABLE','DISABLE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ENABLE',
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `waf_responsefreq_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1010 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.waf_secondfreqlimit
DROP TABLE IF EXISTS `waf_secondfreqlimit`;
CREATE TABLE IF NOT EXISTS `waf_secondfreqlimit` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `url` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `request_count` int NOT NULL DEFAULT '0',
  `burst` int NOT NULL DEFAULT '0',
  `behavior` enum('Deny','Drop','Drop+Block') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'Drop',
  `status` enum('ENABLE','DISABLE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ENABLE',
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `waf_secondfreqlimit_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1009 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.waf_useragent
DROP TABLE IF EXISTS `waf_useragent`;
CREATE TABLE IF NOT EXISTS `waf_useragent` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `url` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `user_agent` varchar(500) NOT NULL DEFAULT '0',
  `match` enum('Equals','Contains','Regex') NOT NULL DEFAULT 'Equals',
  `behavior` enum('Deny','Drop','Drop+Block') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'Drop',
  `status` enum('ENABLE','DISABLE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ENABLE',
  `created_at` timestamp NULL DEFAULT (now()),
  `updated_at` timestamp NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `server_id` (`server_id`) USING BTREE,
  CONSTRAINT `waf_useragent_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1010 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for table cdnproxy.waf_whitelist
DROP TABLE IF EXISTS `waf_whitelist`;
CREATE TABLE IF NOT EXISTS `waf_whitelist` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` bigint NOT NULL,
  `white_ip_list` varchar(255) NOT NULL,
  `url` varchar(500) NOT NULL,
  `method` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` text,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `server_id` (`server_id`),
  CONSTRAINT `waf_whitelist_ibfk_1` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1015 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data exporting was unselected.

-- Dumping structure for trigger cdnproxy.trg_create_l4_defense_on_server_insert
DROP TRIGGER IF EXISTS `trg_create_l4_defense_on_server_insert`;
SET @OLDTMP_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';
DELIMITER //
CREATE TRIGGER `trg_create_l4_defense_on_server_insert` BEFORE INSERT ON `servers` FOR EACH ROW BEGIN
    DECLARE new_l4_id INT;
    
    IF NEW.l4_id IS NULL THEN
        -- Insert default DDoS defense configuration
        INSERT INTO l4_ddos_defense () VALUES ();
        
        SET new_l4_id = LAST_INSERT_ID();
        SET NEW.l4_id = new_l4_id;
    END IF;
END//
DELIMITER ;
SET SQL_MODE=@OLDTMP_SQL_MODE;

-- Dumping structure for trigger cdnproxy.trg_delete_l4_defense_on_server_delete
DROP TRIGGER IF EXISTS `trg_delete_l4_defense_on_server_delete`;
SET @OLDTMP_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';
DELIMITER //
CREATE TRIGGER `trg_delete_l4_defense_on_server_delete` AFTER DELETE ON `servers` FOR EACH ROW BEGIN
    IF OLD.l4_id IS NOT NULL THEN
        DELETE FROM l4_ddos_defense WHERE id = OLD.l4_id;
    END IF;
END//
DELIMITER ;
SET SQL_MODE=@OLDTMP_SQL_MODE;

-- Dumping structure for trigger cdnproxy.trg_prevent_l4_id_update
DROP TRIGGER IF EXISTS `trg_prevent_l4_id_update`;
SET @OLDTMP_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';
DELIMITER //
CREATE TRIGGER `trg_prevent_l4_id_update` BEFORE UPDATE ON `servers` FOR EACH ROW BEGIN
    -- If changing l4_id and old value exists, delete the old defense settings
    IF NEW.l4_id != OLD.l4_id AND OLD.l4_id IS NOT NULL THEN
        DELETE FROM l4_ddos_defense WHERE id = OLD.l4_id;
    END IF;
END//
DELIMITER ;
SET SQL_MODE=@OLDTMP_SQL_MODE;

/*!40103 SET TIME_ZONE=IFNULL(@OLD_TIME_ZONE, 'system') */;
/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IFNULL(@OLD_FOREIGN_KEY_CHECKS, 1) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40111 SET SQL_NOTES=IFNULL(@OLD_SQL_NOTES, 1) */;
