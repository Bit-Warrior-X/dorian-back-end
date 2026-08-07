package store

import (
	"context"
	"database/sql"
	"time"
)

type L4TrafficPoint struct {
	Timestamp      string `json:"timestamp"`
	TotalTraffic   int64  `json:"totalTraffic"`
	AllowedTraffic int64  `json:"allowedTraffic"`
	BlockedTraffic int64  `json:"blockedTraffic"`
}

type L4ProtocolPoint struct {
	Timestamp string `json:"timestamp"`
	Tcp       int64  `json:"tcp"`
	Udp       int64  `json:"udp"`
	Icmp      int64  `json:"icmp"`
	Gre       int64  `json:"gre"`
	Other     int64  `json:"other"`
}

type L4AttackRow struct {
	Timestamp  string `json:"timestamp"`
	SourceIP   string `json:"sourceIp"`
	AttackType string `json:"attackType"`
}

type L4TopIpRow struct {
	IP       string `json:"ip"`
	Count    int64  `json:"count"`
	LastSeen string `json:"lastSeen"`
}

type L4AttackStatsStore interface {
	SumTrafficTotals(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, int64, int64, error)
	ListTrafficSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]L4TrafficPoint, error)
	ListProtocolSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]L4ProtocolPoint, error)
	ListRecentAttacks(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]L4AttackRow, error)
	ListTopAttackIPs(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]L4TopIpRow, error)
}

type l4AttackStatsStore struct {
	db *sql.DB
}

func NewL4AttackStatsStore(db *sql.DB) L4AttackStatsStore {
	return &l4AttackStatsStore{db: db}
}

func (store *l4AttackStatsStore) SumTrafficTotals(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, int64, int64, error) {
	var total int64
	var allowed int64
	var blocked int64
	query := `
		SELECT
			COALESCE(SUM(total_traffic), 0),
			COALESCE(SUM(allowed_traffic), 0),
			COALESCE(SUM(blocked_traffic), 0)
		FROM l4_attack_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&total, &allowed, &blocked); err != nil {
		return 0, 0, 0, err
	}
	return total, allowed, blocked, nil
}

func (store *l4AttackStatsStore) ListTrafficSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]L4TrafficPoint, error) {
	query := `
		SELECT bucket_ts,
		       SUM(total_traffic) AS total_traffic,
		       SUM(allowed_traffic) AS allowed_traffic,
		       SUM(blocked_traffic) AS blocked_traffic
		FROM l4_attack_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []L4TrafficPoint
	for rows.Next() {
		var item L4TrafficPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.TotalTraffic, &item.AllowedTraffic, &item.BlockedTraffic); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *l4AttackStatsStore) ListProtocolSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]L4ProtocolPoint, error) {
	query := `
		SELECT bucket_ts,
		       SUM(tcp) AS tcp,
		       SUM(udp) AS udp,
		       SUM(icmp) AS icmp,
		       SUM(gre) AS gre,
		       SUM(other) AS other
		FROM l4_attack_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []L4ProtocolPoint
	for rows.Next() {
		var item L4ProtocolPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Tcp, &item.Udp, &item.Icmp, &item.Gre, &item.Other); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *l4AttackStatsStore) ListRecentAttacks(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]L4AttackRow, error) {
	if limit <= 0 {
		limit = 10
	}
	query := `
		SELECT source_ip, attack_type, created_at
		FROM l4_live_attack
		WHERE created_at >= ? AND created_at <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []L4AttackRow
	for rows.Next() {
		var row L4AttackRow
		var created time.Time
		if err := rows.Scan(&row.SourceIP, &row.AttackType, &created); err != nil {
			return nil, err
		}
		row.Timestamp = created.Format(time.RFC3339)
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *l4AttackStatsStore) ListTopAttackIPs(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]L4TopIpRow, error) {
	if limit <= 0 {
		limit = 10
	}
	query := `
		SELECT source_ip,
		       COUNT(*) AS seen_count,
		       MAX(created_at) AS last_seen
		FROM l4_live_attack
		WHERE created_at >= ? AND created_at <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY source_ip
		ORDER BY seen_count DESC
		LIMIT ?`
	args = append(args, limit)
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []L4TopIpRow
	for rows.Next() {
		var row L4TopIpRow
		var lastSeen time.Time
		if err := rows.Scan(&row.IP, &row.Count, &lastSeen); err != nil {
			return nil, err
		}
		row.LastSeen = lastSeen.Format(time.RFC3339)
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}
