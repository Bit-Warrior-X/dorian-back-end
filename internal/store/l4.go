package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type L4Config struct {
	ID                      int64    `json:"id"`
	Dev                     string   `json:"dev"`
	AttachMode              string   `json:"attachMode"`
	Sensitivity             string   `json:"sensitivity"`
	ProtectionMode          string   `json:"protectionMode"`
	BlackIPDuration         int      `json:"blackIpDuration"`
	SynValid                bool     `json:"synValid"`
	SynThreshold            int      `json:"synThreshold"`
	SynBurstPkt             int      `json:"synBurstPkt"`
	SynBurstCountPerSec     int      `json:"synBurstCountPerSec"`
	SynFixedThreshold       int      `json:"synFixedThreshold"`
	SynFixedCheckDuration   int      `json:"synFixedCheckDuration"`
	ChallengeTimeout        int      `json:"challengeTimeout"`
	SynProtectionDuration   int      `json:"synProtectionDuration"`
	AckValid                bool     `json:"ackValid"`
	AckThreshold            int      `json:"ackThreshold"`
	AckBurstPkt             int      `json:"ackBurstPkt"`
	AckBurstCountPerSec     int      `json:"ackBurstCountPerSec"`
	AckFixedThreshold       int      `json:"ackFixedThreshold"`
	AckFixedCheckDuration   int      `json:"ackFixedCheckDuration"`
	AckProtectionDuration   int      `json:"ackProtectionDuration"`
	RstValid                bool     `json:"rstValid"`
	RstThreshold            int      `json:"rstThreshold"`
	RstBurstPkt             int      `json:"rstBurstPkt"`
	RstBurstCountPerSec     int      `json:"rstBurstCountPerSec"`
	RstFixedThreshold       int      `json:"rstFixedThreshold"`
	RstFixedCheckDuration   int      `json:"rstFixedCheckDuration"`
	RstProtectionDuration   int      `json:"rstProtectionDuration"`
	IcmpValid               bool     `json:"icmpValid"`
	IcmpThreshold           int      `json:"icmpThreshold"`
	IcmpBurstPkt            int      `json:"icmpBurstPkt"`
	IcmpBurstCountPerSec    int      `json:"icmpBurstCountPerSec"`
	IcmpFixedThreshold      int      `json:"icmpFixedThreshold"`
	IcmpFixedCheckDuration  int      `json:"icmpFixedCheckDuration"`
	IcmpProtectionDuration  int      `json:"icmpProtectionDuration"`
	UdpValid                bool     `json:"udpValid"`
	UdpThreshold            int      `json:"udpThreshold"`
	UdpBurstPkt             int      `json:"udpBurstPkt"`
	UdpBurstCountPerSec     int      `json:"udpBurstCountPerSec"`
	UdpFixedThreshold       int      `json:"udpFixedThreshold"`
	UdpFixedCheckDuration   int      `json:"udpFixedCheckDuration"`
	UdpProtectionDuration   int      `json:"udpProtectionDuration"`
	GreValid                bool     `json:"greValid"`
	GreThreshold            int      `json:"greThreshold"`
	GreBurstPkt             int      `json:"greBurstPkt"`
	GreBurstCountPerSec     int      `json:"greBurstCountPerSec"`
	GreFixedThreshold       int      `json:"greFixedThreshold"`
	GreFixedCheckDuration   int      `json:"greFixedCheckDuration"`
	GreProtectionDuration   int      `json:"greProtectionDuration"`
	TcpSegCheck             bool     `json:"tcpSegCheck"`
	GeoCheck                bool     `json:"geoCheck"`
	GeoDbIpv4Path           string   `json:"geoDbIpv4Path"`
	GeoDbLocationPath       string   `json:"geoDbLocationPath"`
	GeoAllowCountries       []string `json:"geoAllowCountries"`
	GeoCountriesBlockMode   bool     `json:"geoCountriesBlockMode"`
	TcpConnectionLimitCheck bool     `json:"tcpConnectionLimitCheck"`
	TcpConnectionLimitCnt   int      `json:"tcpConnectionLimitCnt"`
}

type L4Store interface {
	GetByServerID(ctx context.Context, serverID int64) (L4Config, error)
	UpdateByServerID(ctx context.Context, serverID int64, config L4Config) error
}

type l4Store struct {
	db *sql.DB
}

func NewL4Store(db *sql.DB) L4Store {
	return &l4Store{db: db}
}

func (store *l4Store) GetByServerID(ctx context.Context, serverID int64) (L4Config, error) {
	l4ID, err := store.getL4ID(ctx, serverID)
	if err != nil {
		return L4Config{}, err
	}
	return store.getByID(ctx, l4ID)
}

func (store *l4Store) UpdateByServerID(ctx context.Context, serverID int64, config L4Config) error {
	l4ID, err := store.getL4ID(ctx, serverID)
	if err != nil {
		return err
	}
	config.ID = l4ID
	return store.update(ctx, config)
}

func (store *l4Store) getL4ID(ctx context.Context, serverID int64) (int64, error) {
	var l4ID sql.NullInt64
	row := store.db.QueryRowContext(ctx, `SELECT l4_id FROM servers WHERE id = ?`, serverID)
	if err := row.Scan(&l4ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errNotFound
		}
		return 0, err
	}
	if !l4ID.Valid || l4ID.Int64 == 0 {
		return 0, errNotFound
	}
	return l4ID.Int64, nil
}

func (store *l4Store) getByID(ctx context.Context, id int64) (L4Config, error) {
	row := store.db.QueryRowContext(ctx, `
		SELECT
			id, dev, attach_mode, sensitivity, protection_mode, black_ip_duration,
			syn_valid, syn_threshold, syn_burst_pkt, syn_burst_count_per_sec,
			syn_fixed_threshold, syn_fixed_check_duration, challenge_timeout, syn_protection_duration,
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
			tcp_seg_check, geo_check, geo_db_ipv4_path, geo_db_location_path, geo_allow_countries, geo_countries_block_mode,
			tcp_connection_limit_check, tcp_connection_limit_cnt
		FROM l4_ddos_defense
		WHERE id = ?`, id)

	var cfg L4Config
	var dev sql.NullString
	var attachMode sql.NullString
	var sensitivity sql.NullString
	var protectionMode sql.NullString
	var geoDbIpv4 sql.NullString
	var geoDbLocation sql.NullString
	var geoAllow sql.NullString
	var geoCountriesBlock sql.NullInt64
	if err := row.Scan(
		&cfg.ID,
		&dev,
		&attachMode,
		&sensitivity,
		&protectionMode,
		&cfg.BlackIPDuration,
		&cfg.SynValid,
		&cfg.SynThreshold,
		&cfg.SynBurstPkt,
		&cfg.SynBurstCountPerSec,
		&cfg.SynFixedThreshold,
		&cfg.SynFixedCheckDuration,
		&cfg.ChallengeTimeout,
		&cfg.SynProtectionDuration,
		&cfg.AckValid,
		&cfg.AckThreshold,
		&cfg.AckBurstPkt,
		&cfg.AckBurstCountPerSec,
		&cfg.AckFixedThreshold,
		&cfg.AckFixedCheckDuration,
		&cfg.AckProtectionDuration,
		&cfg.RstValid,
		&cfg.RstThreshold,
		&cfg.RstBurstPkt,
		&cfg.RstBurstCountPerSec,
		&cfg.RstFixedThreshold,
		&cfg.RstFixedCheckDuration,
		&cfg.RstProtectionDuration,
		&cfg.IcmpValid,
		&cfg.IcmpThreshold,
		&cfg.IcmpBurstPkt,
		&cfg.IcmpBurstCountPerSec,
		&cfg.IcmpFixedThreshold,
		&cfg.IcmpFixedCheckDuration,
		&cfg.IcmpProtectionDuration,
		&cfg.UdpValid,
		&cfg.UdpThreshold,
		&cfg.UdpBurstPkt,
		&cfg.UdpBurstCountPerSec,
		&cfg.UdpFixedThreshold,
		&cfg.UdpFixedCheckDuration,
		&cfg.UdpProtectionDuration,
		&cfg.GreValid,
		&cfg.GreThreshold,
		&cfg.GreBurstPkt,
		&cfg.GreBurstCountPerSec,
		&cfg.GreFixedThreshold,
		&cfg.GreFixedCheckDuration,
		&cfg.GreProtectionDuration,
		&cfg.TcpSegCheck,
		&cfg.GeoCheck,
		&geoDbIpv4,
		&geoDbLocation,
		&geoAllow,
		&geoCountriesBlock,
		&cfg.TcpConnectionLimitCheck,
		&cfg.TcpConnectionLimitCnt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return L4Config{}, errNotFound
		}
		return L4Config{}, err
	}

	cfg.Dev = nullStringValue(dev)
	cfg.AttachMode = nullStringValue(attachMode)
	cfg.Sensitivity = nullStringValue(sensitivity)
	cfg.ProtectionMode = nullStringValue(protectionMode)
	cfg.GeoDbIpv4Path = nullStringValue(geoDbIpv4)
	cfg.GeoDbLocationPath = nullStringValue(geoDbLocation)
	cfg.GeoAllowCountries = splitCSV(nullStringValue(geoAllow))
	cfg.GeoCountriesBlockMode = geoCountriesBlock.Valid && geoCountriesBlock.Int64 != 0

	return cfg, nil
}

func (store *l4Store) update(ctx context.Context, cfg L4Config) error {
	_, err := store.db.ExecContext(ctx, `
		UPDATE l4_ddos_defense SET
			dev = ?, attach_mode = ?, sensitivity = ?, protection_mode = ?, black_ip_duration = ?,
			syn_valid = ?, syn_threshold = ?, syn_burst_pkt = ?, syn_burst_count_per_sec = ?,
			syn_fixed_threshold = ?, syn_fixed_check_duration = ?, challenge_timeout = ?, syn_protection_duration = ?,
			ack_valid = ?, ack_threshold = ?, ack_burst_pkt = ?, ack_burst_count_per_sec = ?,
			ack_fixed_threshold = ?, ack_fixed_check_duration = ?, ack_protection_duration = ?,
			rst_valid = ?, rst_threshold = ?, rst_burst_pkt = ?, rst_burst_count_per_sec = ?,
			rst_fixed_threshold = ?, rst_fixed_check_duration = ?, rst_protection_duration = ?,
			icmp_valid = ?, icmp_threshold = ?, icmp_burst_pkt = ?, icmp_burst_count_per_sec = ?,
			icmp_fixed_threshold = ?, icmp_fixed_check_duration = ?, icmp_protection_duration = ?,
			udp_valid = ?, udp_threshold = ?, udp_burst_pkt = ?, udp_burst_count_per_sec = ?,
			udp_fixed_threshold = ?, udp_fixed_check_duration = ?, udp_protection_duration = ?,
			gre_valid = ?, gre_threshold = ?, gre_burst_pkt = ?, gre_burst_count_per_sec = ?,
			gre_fixed_threshold = ?, gre_fixed_check_duration = ?, gre_protection_duration = ?,
			tcp_seg_check = ?, geo_check = ?, geo_db_ipv4_path = ?, geo_db_location_path = ?, geo_allow_countries = ?, geo_countries_block_mode = ?,
			tcp_connection_limit_check = ?, tcp_connection_limit_cnt = ?
		WHERE id = ?`,
		nullableServerString(cfg.Dev),
		nullableServerString(cfg.AttachMode),
		nullableServerString(cfg.Sensitivity),
		nullableServerString(cfg.ProtectionMode),
		cfg.BlackIPDuration,
		boolToInt(cfg.SynValid),
		cfg.SynThreshold,
		cfg.SynBurstPkt,
		cfg.SynBurstCountPerSec,
		cfg.SynFixedThreshold,
		cfg.SynFixedCheckDuration,
		cfg.ChallengeTimeout,
		cfg.SynProtectionDuration,
		boolToInt(cfg.AckValid),
		cfg.AckThreshold,
		cfg.AckBurstPkt,
		cfg.AckBurstCountPerSec,
		cfg.AckFixedThreshold,
		cfg.AckFixedCheckDuration,
		cfg.AckProtectionDuration,
		boolToInt(cfg.RstValid),
		cfg.RstThreshold,
		cfg.RstBurstPkt,
		cfg.RstBurstCountPerSec,
		cfg.RstFixedThreshold,
		cfg.RstFixedCheckDuration,
		cfg.RstProtectionDuration,
		boolToInt(cfg.IcmpValid),
		cfg.IcmpThreshold,
		cfg.IcmpBurstPkt,
		cfg.IcmpBurstCountPerSec,
		cfg.IcmpFixedThreshold,
		cfg.IcmpFixedCheckDuration,
		cfg.IcmpProtectionDuration,
		boolToInt(cfg.UdpValid),
		cfg.UdpThreshold,
		cfg.UdpBurstPkt,
		cfg.UdpBurstCountPerSec,
		cfg.UdpFixedThreshold,
		cfg.UdpFixedCheckDuration,
		cfg.UdpProtectionDuration,
		boolToInt(cfg.GreValid),
		cfg.GreThreshold,
		cfg.GreBurstPkt,
		cfg.GreBurstCountPerSec,
		cfg.GreFixedThreshold,
		cfg.GreFixedCheckDuration,
		cfg.GreProtectionDuration,
		boolToInt(cfg.TcpSegCheck),
		boolToInt(cfg.GeoCheck),
		nullableServerString(cfg.GeoDbIpv4Path),
		nullableServerString(cfg.GeoDbLocationPath),
		nullableServerString(strings.Join(cfg.GeoAllowCountries, ",")),
		boolToInt(cfg.GeoCountriesBlockMode),
		boolToInt(cfg.TcpConnectionLimitCheck),
		cfg.TcpConnectionLimitCnt,
		cfg.ID,
	)
	return err
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
