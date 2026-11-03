package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
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
	ServerID   int64  `json:"serverId"`
	ServerName string `json:"serverName,omitempty"`
	ServerIP   string `json:"serverIp,omitempty"`
	ReqID      string `json:"reqId,omitempty"`
}

type L4TopIpRow struct {
	IP          string   `json:"ip"`
	Count       int64    `json:"count"`
	FirstSeen   string   `json:"firstSeen,omitempty"`
	LastSeen    string   `json:"lastSeen"`
	ServerID    int64    `json:"serverId"`
	ServerName  string   `json:"serverName,omitempty"`
	ServerIP    string   `json:"serverIp,omitempty"`
	AttackTypes []string `json:"attackTypes,omitempty"`
}

type L4AttackEventSummary struct {
	Attempts int64 `json:"attempts"`
	Sources  int64 `json:"sources"`
	Edges    int64 `json:"edges"`
}

type L4AttackStatsStore interface {
	SumTrafficTotals(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, int64, int64, error)
	// ListTrafficSeries returns rate samples. When bucket > 0, rows are averaged
	// into that width in SQL so long ranges do not ship every second bucket.
	ListTrafficSeries(ctx context.Context, start, end time.Time, scope TrafficScope, bucket time.Duration) ([]L4TrafficPoint, error)
	ListProtocolSeries(ctx context.Context, start, end time.Time, scope TrafficScope, bucket time.Duration) ([]L4ProtocolPoint, error)
	SummarizeAttacks(ctx context.Context, start, end time.Time, scope TrafficScope) (L4AttackEventSummary, error)
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
	// Long windows: sample indexed on_minute rows and scale, instead of
	// scanning every 1s Sparta row (was multi-ten seconds on 7d+ ranges).
	dur := end.Sub(start)
	var query string
	var args []any
	switch {
	case dur > 2*time.Hour:
		// Sample on_minute rows at a coarse step and scale. Prefer a short IN
		// list (≤~1500 stamps) over MOD/range scans on the write-hot table.
		step := 5 * time.Minute
		scale := int64(300)
		if dur > 7*24*time.Hour {
			step = 30 * time.Minute
			scale = 1800
		} else if dur > 48*time.Hour {
			step = 15 * time.Minute
			scale = 900
		}
		stamps := make([]time.Time, 0, int(dur/step)+2)
		cursor := start.UTC().Truncate(step)
		if cursor.Before(start) {
			cursor = cursor.Add(step)
		}
		for !cursor.After(end) {
			stamps = append(stamps, cursor)
			cursor = cursor.Add(step)
		}
		if len(stamps) == 0 {
			return 0, 0, 0, nil
		}
		placeholders := make([]string, len(stamps))
		args = make([]any, 0, len(stamps))
		for i, ts := range stamps {
			placeholders[i] = "?"
			args = append(args, ts)
		}
		scaleSQL := strconv.FormatInt(scale, 10)
		query = `
		SELECT
			COALESCE(SUM(total_traffic), 0) * ` + scaleSQL + `,
			COALESCE(SUM(allowed_traffic), 0) * ` + scaleSQL + `,
			COALESCE(SUM(blocked_traffic), 0) * ` + scaleSQL + `
		FROM l4_attack_stats
		WHERE on_minute = 1
		  AND bucket_ts IN (` + strings.Join(placeholders, ",") + `)`
	default:
		query = `
		SELECT
			COALESCE(SUM(total_traffic), 0),
			COALESCE(SUM(allowed_traffic), 0),
			COALESCE(SUM(blocked_traffic), 0)
		FROM l4_attack_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
		args = []any{start, end}
	}
	query, args = appendServerScope(query, args, scope)
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&total, &allowed, &blocked); err != nil {
		return 0, 0, 0, err
	}
	return total, allowed, blocked, nil
}

func l4SeriesBucketSeconds(bucket time.Duration) int64 {
	secs := int64(bucket / time.Second)
	if secs < 1 {
		return 1
	}
	return secs
}

func (store *l4AttackStatsStore) ListTrafficSeries(ctx context.Context, start, end time.Time, scope TrafficScope, bucket time.Duration) ([]L4TrafficPoint, error) {
	secs := l4SeriesBucketSeconds(bucket)
	var query string
	var args []any
	if secs <= 1 {
		query = `
		SELECT bucket_ts,
		       SUM(total_traffic) AS total_traffic,
		       SUM(allowed_traffic) AS allowed_traffic,
		       SUM(blocked_traffic) AS blocked_traffic
		FROM l4_attack_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
		args = []any{start, end}
		query, args = appendServerScope(query, args, scope)
		query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts`
	} else {
		// Sparta stores 1s rows. Use indexed on_minute samples and keep one
		// sample per chart bucket (MOD step) — avoids scanning every second and
		// the FLOOR/AVG temp-table that was still ~5–15s on 7–30d ranges.
		step := secs
		if step < 60 {
			step = 60
		}
		query = `
		SELECT bucket_ts,
		       SUM(total_traffic) AS total_traffic,
		       SUM(allowed_traffic) AS allowed_traffic,
		       SUM(blocked_traffic) AS blocked_traffic
		FROM l4_attack_stats
		WHERE on_minute = 1
		  AND MOD(UNIX_TIMESTAMP(bucket_ts), ?) = 0
		  AND bucket_ts >= ? AND bucket_ts <= ?`
		args = []any{step, start, end}
		query, args = appendServerScope(query, args, scope)
		query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts`
	}
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []L4TrafficPoint
	for rows.Next() {
		var item L4TrafficPoint
		var ts time.Time
		if err := rows.Scan(&ts, &item.TotalTraffic, &item.AllowedTraffic, &item.BlockedTraffic); err != nil {
			return nil, err
		}
		item.Timestamp = ts.UTC().Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *l4AttackStatsStore) ListProtocolSeries(ctx context.Context, start, end time.Time, scope TrafficScope, bucket time.Duration) ([]L4ProtocolPoint, error) {
	secs := l4SeriesBucketSeconds(bucket)
	var query string
	var args []any
	if secs <= 1 {
		query = `
		SELECT bucket_ts,
		       SUM(tcp) AS tcp,
		       SUM(udp) AS udp,
		       SUM(icmp) AS icmp,
		       SUM(gre) AS gre,
		       SUM(other) AS other
		FROM l4_attack_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
		args = []any{start, end}
		query, args = appendServerScope(query, args, scope)
		query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts`
	} else {
		step := secs
		if step < 60 {
			step = 60
		}
		query = `
		SELECT bucket_ts,
		       SUM(tcp) AS tcp,
		       SUM(udp) AS udp,
		       SUM(icmp) AS icmp,
		       SUM(gre) AS gre,
		       SUM(other) AS other
		FROM l4_attack_stats
		WHERE on_minute = 1
		  AND MOD(UNIX_TIMESTAMP(bucket_ts), ?) = 0
		  AND bucket_ts >= ? AND bucket_ts <= ?`
		args = []any{step, start, end}
		query, args = appendServerScope(query, args, scope)
		query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts`
	}
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []L4ProtocolPoint
	for rows.Next() {
		var item L4ProtocolPoint
		var ts time.Time
		if err := rows.Scan(&ts, &item.Tcp, &item.Udp, &item.Icmp, &item.Gre, &item.Other); err != nil {
			return nil, err
		}
		item.Timestamp = ts.UTC().Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *l4AttackStatsStore) SummarizeAttacks(ctx context.Context, start, end time.Time, scope TrafficScope) (L4AttackEventSummary, error) {
	query := `
		SELECT COUNT(*),
		       COUNT(DISTINCT a.source_ip),
		       COUNT(DISTINCT a.server_id)
		FROM l4_live_attack a
		WHERE a.created_at >= ? AND a.created_at <= ?`
	args := []any{start, end}
	query, args = appendServerScopePrefixed(query, args, scope, "a")
	var out L4AttackEventSummary
	if err := store.db.QueryRowContext(ctx, query, args...).Scan(&out.Attempts, &out.Sources, &out.Edges); err != nil {
		return L4AttackEventSummary{}, err
	}
	return out, nil
}

func (store *l4AttackStatsStore) ListRecentAttacks(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]L4AttackRow, error) {
	if limit <= 0 {
		limit = 10
	}
	query := `
		SELECT a.source_ip, a.attack_type, a.created_at, a.server_id,
		       COALESCE(s.name, ''), COALESCE(s.ip, ''), COALESCE(a.req_id, '')
		FROM l4_live_attack a
		LEFT JOIN servers s ON s.id = a.server_id
		WHERE a.created_at >= ? AND a.created_at <= ?`
	args := []any{start, end}
	query, args = appendServerScopePrefixed(query, args, scope, "a")
	query += ` ORDER BY a.created_at DESC LIMIT ?`
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
		if err := rows.Scan(&row.SourceIP, &row.AttackType, &created, &row.ServerID, &row.ServerName, &row.ServerIP, &row.ReqID); err != nil {
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
		SELECT a.source_ip,
		       a.server_id,
		       COALESCE(s.name, ''),
		       COALESCE(s.ip, ''),
		       COUNT(*) AS seen_count,
		       MIN(a.created_at) AS first_seen,
		       MAX(a.created_at) AS last_seen,
		       GROUP_CONCAT(DISTINCT a.attack_type ORDER BY a.attack_type SEPARATOR ',')
		FROM l4_live_attack a
		LEFT JOIN servers s ON s.id = a.server_id
		WHERE a.created_at >= ? AND a.created_at <= ?`
	args := []any{start, end}
	query, args = appendServerScopePrefixed(query, args, scope, "a")
	query += `
		GROUP BY a.source_ip, a.server_id, s.name, s.ip
		ORDER BY seen_count DESC, last_seen DESC
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
		var firstSeen, lastSeen time.Time
		var typesRaw sql.NullString
		if err := rows.Scan(&row.IP, &row.ServerID, &row.ServerName, &row.ServerIP, &row.Count, &firstSeen, &lastSeen, &typesRaw); err != nil {
			return nil, err
		}
		row.FirstSeen = firstSeen.Format(time.RFC3339)
		row.LastSeen = lastSeen.Format(time.RFC3339)
		if typesRaw.Valid && typesRaw.String != "" {
			row.AttackTypes = splitCSV(typesRaw.String)
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}
