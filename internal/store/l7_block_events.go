package store

import (
	"context"
	"database/sql"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
	"time"
)

type L7BlockEventInput struct {
	ServerID    int64
	SiteID      int64
	SourceIP    string
	URL         string
	TriggerRule string
	Country     string
	City        string
	TTLSeconds  int64
	BlockedAt   time.Time
}

type L7BlockEventRow struct {
	ID          int64  `json:"id"`
	ServerID    int64  `json:"serverId"`
	ServerName  string `json:"serverName"`
	ServerIP    string `json:"serverIp"`
	SiteID      int64  `json:"siteId"`
	SiteDomain  string `json:"siteDomain,omitempty"`
	SourceIP    string `json:"sourceIp"`
	URL         string `json:"url"`
	TriggerRule string `json:"triggerRule"`
	Country     string `json:"country"`
	City        string `json:"city"`
	TTLSeconds  int64  `json:"ttlSeconds"`
	BlockedAt   string `json:"blockedAt"`
	Timestamp   string `json:"timestamp"`
}

type L7TopIPRow struct {
	IP          string   `json:"ip"`
	ServerID    int64    `json:"serverId"`
	ServerName  string   `json:"serverName"`
	ServerIP    string   `json:"serverIp"`
	Count       int64    `json:"count"`
	FirstSeen   string   `json:"firstSeen"`
	LastSeen    string   `json:"lastSeen"`
	TriggerRules []string `json:"triggerRules"`
	URLs        []string `json:"urls,omitempty"`
}

type L7TopURLRow struct {
	URL          string   `json:"url"`
	SiteID       int64    `json:"siteId"`
	SiteDomain   string   `json:"siteDomain,omitempty"`
	Count        int64    `json:"count"`
	UniqueIPs    int64    `json:"uniqueIps"`
	FirstSeen    string   `json:"firstSeen"`
	LastSeen     string   `json:"lastSeen"`
	TriggerRules []string `json:"triggerRules"`
}

type L7BlockEventSummary struct {
	Events  int64 `json:"events"`
	Sources int64 `json:"sources"`
	URLs    int64 `json:"urls"`
}

type L7BlockEventStore interface {
	Record(ctx context.Context, input L7BlockEventInput) error
	RecordMany(ctx context.Context, inputs []L7BlockEventInput) error
	Summarize(ctx context.Context, start, end time.Time, scope TrafficScope) (L7BlockEventSummary, error)
	ListRecent(ctx context.Context, start, end time.Time, scope TrafficScope, limit int, sourceIP string) ([]L7BlockEventRow, error)
	ListTopIPs(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]L7TopIPRow, error)
	ListTopURLs(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]L7TopURLRow, error)
}

type l7BlockEventStore struct {
	db *sql.DB
}

func NewL7BlockEventStore(db *sql.DB) L7BlockEventStore {
	return &l7BlockEventStore{db: db}
}

func normalizeBlockedAt(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC().Truncate(time.Second)
	}
	return t.UTC().Truncate(time.Second)
}

func urlHash(raw string) uint32 {
	return crc32.ChecksumIEEE([]byte(strings.TrimSpace(raw)))
}

func (store *l7BlockEventStore) Record(ctx context.Context, input L7BlockEventInput) error {
	return store.RecordMany(ctx, []L7BlockEventInput{input})
}

func (store *l7BlockEventStore) RecordMany(ctx context.Context, inputs []L7BlockEventInput) error {
	if len(inputs) == 0 {
		return nil
	}
	placeholders := make([]string, 0, len(inputs))
	args := make([]any, 0, len(inputs)*11)
	for _, in := range inputs {
		ip := strings.TrimSpace(in.SourceIP)
		if in.ServerID <= 0 || ip == "" {
			continue
		}
		url := strings.TrimSpace(in.URL)
		if len(url) > 2048 {
			url = url[:2048]
		}
		rule := strings.TrimSpace(in.TriggerRule)
		if len(rule) > 128 {
			rule = rule[:128]
		}
		blockedAt := normalizeBlockedAt(in.BlockedAt)
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		args = append(args,
			in.ServerID,
			in.SiteID,
			ip,
			url,
			urlHash(url),
			rule,
			strings.TrimSpace(in.Country),
			strings.TrimSpace(in.City),
			in.TTLSeconds,
			blockedAt,
		)
	}
	if len(placeholders) == 0 {
		return nil
	}
	query := `
		INSERT INTO l7_block_events (
			server_id, site_id, source_ip, request_url, url_hash,
			trigger_rule, country, city, ttl_seconds, blocked_at
		) VALUES ` + strings.Join(placeholders, ",") + `
		ON DUPLICATE KEY UPDATE
			site_id = VALUES(site_id),
			country = IF(VALUES(country) != '', VALUES(country), country),
			city = IF(VALUES(city) != '', VALUES(city), city),
			ttl_seconds = GREATEST(ttl_seconds, VALUES(ttl_seconds))`
	_, err := store.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("insert l7_block_events: %w", err)
	}
	return nil
}

func appendL7EventScope(query string, args []any, scope TrafficScope) (string, []any) {
	query, args = appendServerScopePrefixed(query, args, scope, "e")
	if scope.SiteID > 0 {
		query += ` AND e.site_id = ?`
		args = append(args, scope.SiteID)
	}
	return query, args
}

func (store *l7BlockEventStore) Summarize(ctx context.Context, start, end time.Time, scope TrafficScope) (L7BlockEventSummary, error) {
	query := `
		SELECT COUNT(*),
		       COUNT(DISTINCT e.source_ip),
		       COUNT(DISTINCT NULLIF(e.request_url, ''))
		FROM l7_block_events e
		WHERE e.blocked_at >= ? AND e.blocked_at <= ?`
	args := []any{start, end}
	query, args = appendL7EventScope(query, args, scope)
	var out L7BlockEventSummary
	if err := store.db.QueryRowContext(ctx, query, args...).Scan(&out.Events, &out.Sources, &out.URLs); err != nil {
		return L7BlockEventSummary{}, err
	}
	return out, nil
}

func (store *l7BlockEventStore) ListRecent(ctx context.Context, start, end time.Time, scope TrafficScope, limit int, sourceIP string) ([]L7BlockEventRow, error) {
	if limit <= 0 {
		limit = 25
	}
	query := `
		SELECT e.id, e.server_id, COALESCE(s.name, ''), COALESCE(s.ip, ''),
		       e.site_id, COALESCE(si.domain, ''),
		       e.source_ip, e.request_url, e.trigger_rule, e.country, e.city,
		       e.ttl_seconds, e.blocked_at, e.created_at
		FROM l7_block_events e
		LEFT JOIN servers s ON s.id = e.server_id
		LEFT JOIN sites si ON si.id = e.site_id
		WHERE e.blocked_at >= ? AND e.blocked_at <= ?`
	args := []any{start, end}
	query, args = appendL7EventScope(query, args, scope)
	if ip := strings.TrimSpace(sourceIP); ip != "" {
		query += ` AND e.source_ip = ?`
		args = append(args, ip)
	}
	query += ` ORDER BY e.blocked_at DESC, e.id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]L7BlockEventRow, 0)
	for rows.Next() {
		var row L7BlockEventRow
		var blockedAt, created time.Time
		if err := rows.Scan(
			&row.ID, &row.ServerID, &row.ServerName, &row.ServerIP,
			&row.SiteID, &row.SiteDomain,
			&row.SourceIP, &row.URL, &row.TriggerRule, &row.Country, &row.City,
			&row.TTLSeconds, &blockedAt, &created,
		); err != nil {
			return nil, err
		}
		row.BlockedAt = blockedAt.Format(time.RFC3339)
		row.Timestamp = created.Format(time.RFC3339)
		out = append(out, row)
	}
	return out, rows.Err()
}

func (store *l7BlockEventStore) ListTopIPs(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]L7TopIPRow, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `
		SELECT e.source_ip, e.server_id, COALESCE(s.name, ''), COALESCE(s.ip, ''),
		       COUNT(*) AS seen_count,
		       MIN(e.blocked_at) AS first_seen,
		       MAX(e.blocked_at) AS last_seen,
		       GROUP_CONCAT(DISTINCT NULLIF(e.trigger_rule, '') ORDER BY e.trigger_rule SEPARATOR ',')
		FROM l7_block_events e
		LEFT JOIN servers s ON s.id = e.server_id
		WHERE e.blocked_at >= ? AND e.blocked_at <= ?`
	args := []any{start, end}
	query, args = appendL7EventScope(query, args, scope)
	query += `
		GROUP BY e.source_ip, e.server_id, s.name, s.ip
		ORDER BY seen_count DESC, last_seen DESC
		LIMIT ?`
	args = append(args, limit)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]L7TopIPRow, 0)
	for rows.Next() {
		var row L7TopIPRow
		var first, last time.Time
		var rulesRaw sql.NullString
		if err := rows.Scan(&row.IP, &row.ServerID, &row.ServerName, &row.ServerIP, &row.Count, &first, &last, &rulesRaw); err != nil {
			return nil, err
		}
		row.FirstSeen = first.Format(time.RFC3339)
		row.LastSeen = last.Format(time.RFC3339)
		if rulesRaw.Valid && rulesRaw.String != "" {
			row.TriggerRules = splitCSV(rulesRaw.String)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (store *l7BlockEventStore) ListTopURLs(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]L7TopURLRow, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `
		SELECT e.request_url, e.site_id, COALESCE(si.domain, ''),
		       COUNT(*) AS seen_count,
		       COUNT(DISTINCT e.source_ip) AS unique_ips,
		       MIN(e.blocked_at) AS first_seen,
		       MAX(e.blocked_at) AS last_seen,
		       GROUP_CONCAT(DISTINCT NULLIF(e.trigger_rule, '') ORDER BY e.trigger_rule SEPARATOR ',')
		FROM l7_block_events e
		LEFT JOIN sites si ON si.id = e.site_id
		WHERE e.blocked_at >= ? AND e.blocked_at <= ?
		  AND e.request_url != ''`
	args := []any{start, end}
	query, args = appendL7EventScope(query, args, scope)
	query += `
		GROUP BY e.request_url, e.site_id, si.domain
		ORDER BY seen_count DESC, last_seen DESC
		LIMIT ?`
	args = append(args, limit)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]L7TopURLRow, 0)
	for rows.Next() {
		var row L7TopURLRow
		var first, last time.Time
		var rulesRaw sql.NullString
		if err := rows.Scan(&row.URL, &row.SiteID, &row.SiteDomain, &row.Count, &row.UniqueIPs, &first, &last, &rulesRaw); err != nil {
			return nil, err
		}
		row.FirstSeen = first.Format(time.RFC3339)
		row.LastSeen = last.Format(time.RFC3339)
		if rulesRaw.Valid && rulesRaw.String != "" {
			row.TriggerRules = splitCSV(rulesRaw.String)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// L7BlockEventFromTempPayload converts a live temporary-block report into a durable event.
func L7BlockEventFromTempPayload(p TemporaryBlacklistPayload) (L7BlockEventInput, bool) {
	ip := strings.TrimSpace(p.IP)
	if p.ServerID <= 0 || ip == "" {
		return L7BlockEventInput{}, false
	}
	rule := strings.TrimSpace(p.TriggerRule)
	if isL4TriggerRule(rule) {
		return L7BlockEventInput{}, false
	}
	blockedAt := time.Now().UTC()
	if raw := strings.TrimSpace(p.BlockedAt); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			blockedAt = parsed
		} else if parsed, err := time.ParseInLocation("2006-01-02 15:04:05", raw, time.UTC); err == nil {
			blockedAt = parsed
		} else if unix, err := strconv.ParseInt(raw, 10, 64); err == nil && unix > 0 {
			// Angelos sometimes sends unix seconds (or ms).
			if unix > 1_000_000_000_000 {
				blockedAt = time.UnixMilli(unix).UTC()
			} else {
				blockedAt = time.Unix(unix, 0).UTC()
			}
		}
	}
	return L7BlockEventInput{
		ServerID:    p.ServerID,
		SiteID:      p.SiteID,
		SourceIP:    ip,
		URL:         strings.TrimSpace(p.URL),
		TriggerRule: rule,
		Country:     strings.TrimSpace(p.Country),
		City:        strings.TrimSpace(p.City),
		TTLSeconds:  p.TTL,
		BlockedAt:   blockedAt,
	}, true
}

func isL4TriggerRule(rule string) bool {
	rule = strings.ToLower(strings.TrimSpace(rule))
	return rule == "l4ddos" || strings.HasPrefix(rule, "l4")
}
