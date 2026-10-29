package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type SecurityEvent struct {
	ID          int64  `json:"id"`
	ServerID    *int64 `json:"serverId,omitempty"`
	ServerName  string `json:"serverName,omitempty"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
	SourceIP    string `json:"sourceIp,omitempty"`
	TTL         string `json:"ttl,omitempty"`
	AttackType  string `json:"attackType,omitempty"`
	Data        string `json:"data,omitempty"`
	ReqID       string `json:"reqId,omitempty"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

// SecurityEventPeriod is one attack window. Reports that share a req_id belong together.
type SecurityEventPeriod struct {
	ID          string   `json:"id"`
	ReqID       string   `json:"reqId,omitempty"`
	ServerID    *int64   `json:"serverId,omitempty"`
	ServerName  string   `json:"serverName,omitempty"`
	Layer       string   `json:"layer,omitempty"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	AttackType  string   `json:"attackType,omitempty"`
	Status      string   `json:"status"`
	StartedAt   string   `json:"startedAt"`
	EndedAt     string   `json:"endedAt,omitempty"`
	CreatedAt   string   `json:"createdAt"`
	BlockedIPs  []string `json:"blockedIps,omitempty"`
	IPCount     int      `json:"ipCount"`
	EventCount  int      `json:"eventCount"`
	// ActiveIPCount is filled by ListPeriods: sources still inside their block TTL.
	ActiveIPCount int  `json:"activeIpCount"`
	StopReported  bool `json:"stopReported"`
	// Vectors counts distinct blocked sources per raw attack type, largest first.
	Vectors []PeriodVector  `json:"vectors,omitempty"`
	Events  []SecurityEvent `json:"events,omitempty"`
}

type PeriodVector struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// attackQuietTimeout ends an attack that never reported attack_stop. Edges re-report
// blocks every TTL while an attack runs, so this long without a report means it is over.
const attackQuietTimeout = 15 * time.Minute

// SecurityEventReport is the edge report behind a security event.
type SecurityEventReport struct {
	Command    string
	SourceIP   string
	TTL        string
	AttackType string
	Data       string
	ReqID      string
}

type SecurityEventStore interface {
	ListRecent(ctx context.Context, limit int, scope TrafficScope) ([]SecurityEvent, error)
	// ListPeriods returns the newest attack windows, grouping reports that share a req_id.
	// When start and end are non-zero, only periods that overlap [start, end) are returned.
	ListPeriods(ctx context.Context, limit int, scope TrafficScope, start, end time.Time) ([]SecurityEventPeriod, error)
	// GetPeriod returns one attack window by its req_id.
	GetPeriod(ctx context.Context, reqID string) (SecurityEventPeriod, error)
	// Create records an event reported by an edge; serverID 0 stores no edge.
	// occurredAt is the time the event happened and is stored as created_at.
	Create(ctx context.Context, serverID int64, title, description string, occurredAt time.Time, report SecurityEventReport) error
	// ListBlockedSources returns one row per source IP blocked under req_id.
	// limit caps the result (most recently blocked first). 0 uses 200.
	ListBlockedSources(ctx context.Context, serverID int64, reqID string, limit int) ([]BlockedSource, error)
	// ListBlockedSourcesPage returns a slice of blocked sources, optionally
	// filtered by IP prefix/contains and whether the block is still active.
	ListBlockedSourcesPage(ctx context.Context, serverID int64, reqID string, offset, limit int, match string, activeOnly bool) ([]BlockedSource, error)
	// CountPeriodsStarted counts attack windows (same grouping as ListPeriods) that began in [start, end).
	CountPeriodsStarted(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, error)
}

// BlockedSource is a source IP blocked during one attack. LastBlockedAt plus TTL is
// when the edge releases it.
type BlockedSource struct {
	IP            string
	AttackType    string
	TTL           string
	FirstBlocked  time.Time
	LastBlockedAt time.Time
	Blocks        int
}

func (store *securityEventStore) CountPeriodsStarted(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, error) {
	// Look back one day so a window already open at start keeps its real first report.
	inner, args := appendServerScope(`
		SELECT IF(req_id = '', CONCAT('event:', id), req_id) AS period_key, MIN(created_at) AS started_at
		FROM security_events
		WHERE (req_id <> '' OR event_data = 'attack_start')
		  AND created_at >= ? AND created_at < ?`, []any{start.Add(-24 * time.Hour), end}, scope)
	query := `SELECT COUNT(*) FROM (` + inner + ` GROUP BY period_key) p WHERE p.started_at >= ? AND p.started_at < ?`
	args = append(args, start, end)
	var total int64
	if err := store.db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *securityEventStore) ListBlockedSources(ctx context.Context, serverID int64, reqID string, limit int) ([]BlockedSource, error) {
	reqID = strings.TrimSpace(reqID)
	if reqID == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	query := `
		SELECT e.source_ip,
			SUBSTRING_INDEX(GROUP_CONCAT(e.attack_type ORDER BY e.created_at DESC SEPARATOR '\n'), '\n', 1),
			SUBSTRING_INDEX(GROUP_CONCAT(e.ttl ORDER BY e.created_at DESC SEPARATOR '\n'), '\n', 1),
			MIN(e.created_at), MAX(e.created_at), COUNT(*)
		FROM security_events e
		WHERE e.req_id = ? AND e.command = 'report_block_ip' AND e.source_ip <> ''`
	args := []any{reqID}
	if serverID > 0 {
		query += ` AND e.server_id = ?`
		args = append(args, serverID)
	}
	query += ` GROUP BY e.source_ip ORDER BY MAX(e.created_at) DESC LIMIT ?`
	args = append(args, limit)
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlockedSource
	for rows.Next() {
		var item BlockedSource
		var attackType, ttl sql.NullString
		var first, last sql.NullTime
		if err := rows.Scan(&item.IP, &attackType, &ttl, &first, &last, &item.Blocks); err != nil {
			return nil, err
		}
		item.AttackType = attackType.String
		item.TTL = ttl.String
		item.FirstBlocked = first.Time.UTC()
		item.LastBlockedAt = last.Time.UTC()
		out = append(out, item)
	}
	return out, rows.Err()
}

func sanitizeSourceMatch(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '.' || r == ':' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 64 {
		return out[:64]
	}
	return out
}

func (store *securityEventStore) ListBlockedSourcesPage(ctx context.Context, serverID int64, reqID string, offset, limit int, match string, activeOnly bool) ([]BlockedSource, error) {
	reqID = strings.TrimSpace(reqID)
	if reqID == "" {
		return nil, nil
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	match = sanitizeSourceMatch(match)

	query := `
		SELECT source_ip, attack_type, ttl, first_at, last_at, blocks
		FROM (
			SELECT e.source_ip,
				SUBSTRING_INDEX(GROUP_CONCAT(e.attack_type ORDER BY e.created_at DESC SEPARATOR '\n'), '\n', 1) AS attack_type,
				SUBSTRING_INDEX(GROUP_CONCAT(e.ttl ORDER BY e.created_at DESC SEPARATOR '\n'), '\n', 1) AS ttl,
				MIN(e.created_at) AS first_at,
				MAX(e.created_at) AS last_at,
				COUNT(*) AS blocks,
				MAX(CAST(REPLACE(LOWER(e.ttl), 's', '') AS UNSIGNED)) AS ttl_seconds
			FROM security_events e
			WHERE e.req_id = ? AND e.command = 'report_block_ip' AND e.source_ip <> ''`
	args := []any{reqID}
	if serverID > 0 {
		query += ` AND e.server_id = ?`
		args = append(args, serverID)
	}
	if match != "" {
		query += ` AND e.source_ip LIKE ?`
		args = append(args, "%"+match+"%")
	}
	query += `
			GROUP BY e.source_ip
		) blocks`
	if activeOnly {
		query += ` WHERE last_at + INTERVAL IF(ttl_seconds > 0, ttl_seconds, 60) SECOND > UTC_TIMESTAMP()`
	}
	query += ` ORDER BY last_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlockedSource
	for rows.Next() {
		var item BlockedSource
		var attackType, ttl sql.NullString
		var first, last sql.NullTime
		if err := rows.Scan(&item.IP, &attackType, &ttl, &first, &last, &item.Blocks); err != nil {
			return nil, err
		}
		item.AttackType = attackType.String
		item.TTL = ttl.String
		item.FirstBlocked = first.Time.UTC()
		item.LastBlockedAt = last.Time.UTC()
		out = append(out, item)
	}
	return out, rows.Err()
}

type securityEventStore struct {
	db *sql.DB
}

func NewSecurityEventStore(db *sql.DB) SecurityEventStore {
	return &securityEventStore{db: db}
}

func (store *securityEventStore) ListRecent(ctx context.Context, limit int, scope TrafficScope) ([]SecurityEvent, error) {
	if limit <= 0 {
		limit = 5
	}
	query, args := appendServerScope(`
		SELECT e.id, e.server_id, s.name, e.title, e.description, e.command, e.source_ip, e.ttl, e.attack_type, e.event_data, e.req_id, e.created_at, e.updated_at
		FROM security_events e
		LEFT JOIN servers s ON s.id = e.server_id
		WHERE 1 = 1`, nil, scope)
	query += " ORDER BY e.created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		var item SecurityEvent
		var serverID sql.NullInt64
		var serverName sql.NullString
		var createdAt sql.NullTime
		var updatedAt sql.NullTime
		if err := rows.Scan(&item.ID, &serverID, &serverName, &item.Title, &item.Description, &item.Command, &item.SourceIP, &item.TTL, &item.AttackType, &item.Data, &item.ReqID, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		if serverID.Valid {
			value := serverID.Int64
			item.ServerID = &value
		}
		item.ServerName = serverName.String
		item.CreatedAt = formatTimestamp(createdAt)
		item.UpdatedAt = formatTimestamp(updatedAt)
		events = append(events, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (store *securityEventStore) Create(ctx context.Context, serverID int64, title, description string, occurredAt time.Time, report SecurityEventReport) error {
	var server any
	if serverID > 0 {
		server = serverID
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now()
	}
	_, err := store.db.ExecContext(ctx, `
		INSERT INTO security_events (server_id, title, description, command, source_ip, ttl, attack_type, event_data, req_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		server,
		title,
		description,
		report.Command,
		report.SourceIP,
		report.TTL,
		report.AttackType,
		report.Data,
		report.ReqID,
		occurredAt,
		occurredAt,
	)
	return err
}

type securityPeriodStats struct {
	eventCount int
	ipCount    int
	started    sql.NullTime
	ended      sql.NullTime
	attackType string
	startedHit bool
	stoppedHit bool
	serverName string
}

func (store *securityEventStore) ListPeriods(ctx context.Context, limit int, scope TrafficScope, start, end time.Time) ([]SecurityEventPeriod, error) {
	if limit <= 0 {
		limit = 6
	}
	// Detection can request the full attack history; keep a hard ceiling for safety.
	if limit > 5000 {
		limit = 5000
	}
	useWindow := !start.IsZero() && !end.IsZero() && end.After(start)
	// Prefer real attack windows (shared req_id). Orphan per-IP block rows without
	// req_id (e.g. EVENT_IP_FRAG_MIDDLE_BLOCK) used to flood the newest-N list and
	// hide ongoing floods from Overview / Alarms.
	var keyQuery string
	var keyArgs []any
	if useWindow {
		// Look back a day so an attack already open at start keeps its real first report,
		// then keep periods that overlap [start, end).
		keyQuery, keyArgs = appendServerScope(`
			SELECT period_key, last_at FROM (
				SELECT IF(req_id = '', CONCAT('event:', id), req_id) AS period_key,
				       MIN(created_at) AS started_at,
				       MAX(created_at) AS last_at
				FROM security_events
				WHERE (req_id <> '' OR event_data IN ('attack_start', 'attack_stop'))
				  AND created_at >= ? AND created_at < ?`, []any{start.Add(-24 * time.Hour), end}, scope)
		keyQuery += `
				GROUP BY period_key
			) p
			WHERE p.started_at < ? AND p.last_at >= ?
			ORDER BY p.last_at DESC
			LIMIT ?`
		keyArgs = append(keyArgs, end, start, limit)
	} else {
		keyQuery, keyArgs = appendServerScope(`
		SELECT IF(req_id = '', CONCAT('event:', id), req_id) AS period_key, MAX(created_at) AS last_at
		FROM security_events
		WHERE (req_id <> '' OR event_data IN ('attack_start', 'attack_stop'))`, nil, scope)
		keyQuery += " GROUP BY period_key ORDER BY last_at DESC LIMIT ?"
		keyArgs = append(keyArgs, limit)
	}
	keyRows, err := store.db.QueryContext(ctx, keyQuery, keyArgs...)
	if err != nil {
		return nil, err
	}
	var order, reqIDs []string
	var eventIDs []any
	for keyRows.Next() {
		var key string
		var last sql.NullTime
		if err := keyRows.Scan(&key, &last); err != nil {
			keyRows.Close()
			return nil, err
		}
		order = append(order, key)
		if id, ok := strings.CutPrefix(key, "event:"); ok {
			eventIDs = append(eventIDs, id)
		} else {
			reqIDs = append(reqIDs, key)
		}
	}
	keyRows.Close()
	if err := keyRows.Err(); err != nil {
		return nil, err
	}
	if len(order) == 0 {
		return []SecurityEventPeriod{}, nil
	}

	latest := map[string]SecurityEvent{}
	if len(reqIDs) > 0 {
		args := make([]any, len(reqIDs))
		for i, id := range reqIDs {
			args[i] = id
		}
		if err := store.scanInto(ctx, latest, `
			SELECT e.id, e.server_id, s.name, e.title, e.description, e.command, e.source_ip, e.ttl, e.attack_type, e.event_data, e.req_id, e.created_at, e.updated_at
			FROM security_events e
			JOIN (SELECT req_id, MAX(id) AS id FROM security_events WHERE req_id IN (`+sqlPlaceholders(len(reqIDs))+`) GROUP BY req_id) m ON m.id = e.id
			LEFT JOIN servers s ON s.id = e.server_id`, args, func(item SecurityEvent) string { return item.ReqID }); err != nil {
			return nil, err
		}
	}
	if len(eventIDs) > 0 {
		if err := store.scanInto(ctx, latest, `
			SELECT e.id, e.server_id, s.name, e.title, e.description, e.command, e.source_ip, e.ttl, e.attack_type, e.event_data, e.req_id, e.created_at, e.updated_at
			FROM security_events e
			LEFT JOIN servers s ON s.id = e.server_id
			WHERE e.id IN (`+sqlPlaceholders(len(eventIDs))+`)`, eventIDs, func(item SecurityEvent) string { return fmt.Sprintf("event:%d", item.ID) }); err != nil {
			return nil, err
		}
	}

	stats, err := store.periodStats(ctx, reqIDs)
	if err != nil {
		return nil, err
	}
	ips, err := store.periodIPs(ctx, reqIDs, 24)
	if err != nil {
		return nil, err
	}
	timeline, err := store.periodTimeline(ctx, reqIDs)
	if err != nil {
		return nil, err
	}
	active, err := store.periodActiveIPs(ctx, reqIDs)
	if err != nil {
		return nil, err
	}
	vectors, err := store.periodVectors(ctx, reqIDs)
	if err != nil {
		return nil, err
	}

	periods := make([]SecurityEventPeriod, 0, len(order))
	for _, key := range order {
		row, ok := latest[key]
		if !ok {
			continue
		}
		if strings.HasPrefix(key, "event:") {
			periods = append(periods, singleSecurityPeriod(row))
			continue
		}
		group := []SecurityEvent{row}
		for i := len(timeline[key]) - 1; i >= 0; i-- {
			group = append(group, timeline[key][i])
		}
		period := groupedSecurityPeriod(key, group, stats[key], ips[key], timeline[key])
		period.ActiveIPCount = active[key]
		period.Vectors = vectors[key]
		if title := multiAttackPeriodTitle(period.Vectors); title != "" {
			period.Title = title
			period.AttackType = period.Vectors[0].Type
		}
		periods = append(periods, period)
	}
	return periods, nil
}

func (store *securityEventStore) scanInto(ctx context.Context, out map[string]SecurityEvent, query string, args []any, key func(SecurityEvent) string) error {
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanSecurityEvent(rows)
		if err != nil {
			return err
		}
		out[key(item)] = item
	}
	return rows.Err()
}

func (store *securityEventStore) periodVectors(ctx context.Context, reqIDs []string) (map[string][]PeriodVector, error) {
	out := map[string][]PeriodVector{}
	if len(reqIDs) == 0 {
		return out, nil
	}
	args := make([]any, len(reqIDs))
	for i, id := range reqIDs {
		args[i] = id
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT req_id, attack_type, COUNT(DISTINCT source_ip) AS sources
		FROM security_events
		WHERE req_id IN (`+sqlPlaceholders(len(reqIDs))+`) AND command = 'report_block_ip' AND attack_type <> ''
		GROUP BY req_id, attack_type
		ORDER BY req_id, sources DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var reqID string
		var rawType string
		var count int
		if err := rows.Scan(&reqID, &rawType, &count); err != nil {
			return nil, err
		}
		label := periodVectorLabel(rawType)
		if label == "" {
			label = strings.TrimSpace(rawType)
		}
		if label == "" {
			continue
		}
		// Collapse duplicate raw types that map to the same label.
		merged := false
		for i := range out[reqID] {
			if out[reqID][i].Type == label {
				out[reqID][i].Count += count
				merged = true
				break
			}
		}
		if !merged {
			out[reqID] = append(out[reqID], PeriodVector{Type: label, Count: count})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// L7 incidents carry vector ids on report_l7_attack rows (no report_block_ip).
	l7Rows, err := store.db.QueryContext(ctx, `
		SELECT req_id, attack_type, MAX(CAST(NULLIF(ttl, '') AS UNSIGNED))
		FROM security_events
		WHERE req_id IN (`+sqlPlaceholders(len(reqIDs))+`) AND command = 'report_l7_attack' AND attack_type <> ''
		GROUP BY req_id, attack_type`, args...)
	if err != nil {
		return out, err
	}
	defer l7Rows.Close()
	for l7Rows.Next() {
		var reqID, rawType string
		var unique sql.NullInt64
		if err := l7Rows.Scan(&reqID, &rawType, &unique); err != nil {
			return out, err
		}
		count := int(unique.Int64)
		if count <= 0 {
			count = 1
		}
		for _, part := range strings.FieldsFunc(rawType, func(r rune) bool {
			return r == '+' || r == ',' || r == '|' || r == '/'
		}) {
			label := L7VectorLabel(part)
			if label == "" {
				label = periodVectorLabel(part)
			}
			if label == "" {
				continue
			}
			merged := false
			for i := range out[reqID] {
				if out[reqID][i].Type == label {
					if count > out[reqID][i].Count {
						out[reqID][i].Count = count
					}
					merged = true
					break
				}
			}
			if !merged {
				out[reqID] = append(out[reqID], PeriodVector{Type: label, Count: count})
			}
		}
	}
	if err := l7Rows.Err(); err != nil {
		return out, err
	}

	// Protection-mode START events reveal vectors that never produced report_block_ip
	// rows (common for RST alongside ACK in the same req_id).
	protRows, err := store.db.QueryContext(ctx, `
		SELECT req_id, event_data
		FROM security_events
		WHERE req_id IN (`+sqlPlaceholders(len(reqIDs))+`) AND command = 'report_protection'
		  AND UPPER(event_data) LIKE '%START%'`, args...)
	if err != nil {
		return out, err
	}
	defer protRows.Close()
	seen := map[string]map[string]struct{}{}
	for reqID, vectors := range out {
		seen[reqID] = map[string]struct{}{}
		for _, item := range vectors {
			seen[reqID][item.Type] = struct{}{}
		}
	}
	for protRows.Next() {
		var reqID, data string
		if err := protRows.Scan(&reqID, &data); err != nil {
			return nil, err
		}
		label := periodVectorLabel(data)
		if label == "" {
			continue
		}
		if seen[reqID] == nil {
			seen[reqID] = map[string]struct{}{}
		}
		if _, ok := seen[reqID][label]; ok {
			continue
		}
		seen[reqID][label] = struct{}{}
		out[reqID] = append(out[reqID], PeriodVector{Type: label, Count: 0})
	}
	return out, protRows.Err()
}

func periodVectorLabel(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	tokens := map[string]bool{}
	for _, token := range strings.FieldsFunc(strings.ToUpper(raw), func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	}) {
		tokens[token] = true
	}
	switch {
	case tokens["SOCKET"], tokens["XMAS"], tokens["NULL"], tokens["FIN"]:
		return "SOCKET"
	case tokens["STOMP"], tokens["PSH"]:
		return "STOMP"
	case tokens["HANDSHAKE"]:
		return "HANDSHAKE"
	case tokens["SYN"]:
		return "TCP SYN"
	case tokens["RST"]:
		return "TCP RST"
	case tokens["ACK"]:
		return "TCP ACK"
	case tokens["UDP"]:
		return "UDP"
	case tokens["ICMP"]:
		return "ICMP"
	case tokens["GRE"]:
		return "GRE"
	case tokens["FLOOD"]:
		return "Flood"
	case tokens["RAPIDRESET"], tokens["RAPID"]:
		return "Rapid Reset"
	case tokens["MALFORMED"]:
		return "Malformed"
	case tokens["BLOCKED"]:
		return "Blocked"
	default:
		return ""
	}
}

// periodActiveIPs counts sources whose latest block has not reached its TTL yet.
func (store *securityEventStore) periodActiveIPs(ctx context.Context, reqIDs []string) (map[string]int, error) {
	out := map[string]int{}
	if len(reqIDs) == 0 {
		return out, nil
	}
	args := make([]any, len(reqIDs))
	for i, id := range reqIDs {
		args[i] = id
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT req_id, COUNT(*)
		FROM (
			SELECT req_id, source_ip, MAX(created_at) AS last_at,
				MAX(CAST(REPLACE(LOWER(ttl), 's', '') AS UNSIGNED)) AS ttl_seconds
			FROM security_events
			WHERE req_id IN (`+sqlPlaceholders(len(reqIDs))+`) AND command = 'report_block_ip' AND source_ip <> ''
			GROUP BY req_id, source_ip
		) blocks
		WHERE last_at + INTERVAL IF(ttl_seconds > 0, ttl_seconds, 60) SECOND > UTC_TIMESTAMP()
		GROUP BY req_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var reqID string
		var count int
		if err := rows.Scan(&reqID, &count); err != nil {
			return nil, err
		}
		out[reqID] = count
	}
	return out, rows.Err()
}

func (store *securityEventStore) GetPeriod(ctx context.Context, reqID string) (SecurityEventPeriod, error) {
	reqID = strings.TrimSpace(reqID)
	if reqID == "" {
		return SecurityEventPeriod{}, errNotFound
	}
	stats, err := store.periodStats(ctx, []string{reqID})
	if err != nil {
		return SecurityEventPeriod{}, err
	}
	if stats[reqID].eventCount == 0 {
		return SecurityEventPeriod{}, errNotFound
	}
	ips, err := store.periodIPs(ctx, []string{reqID}, 40)
	if err != nil {
		return SecurityEventPeriod{}, err
	}
	timeline, err := store.periodTimeline(ctx, []string{reqID})
	if err != nil {
		return SecurityEventPeriod{}, err
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT e.id, e.server_id, s.name, e.title, e.description, e.command, e.source_ip, e.ttl, e.attack_type, e.event_data, e.req_id, e.created_at, e.updated_at
		FROM security_events e
		LEFT JOIN servers s ON s.id = e.server_id
		WHERE e.req_id = ?
		ORDER BY e.created_at DESC
		LIMIT 8`, reqID)
	if err != nil {
		return SecurityEventPeriod{}, err
	}
	defer rows.Close()
	var members []SecurityEvent
	for rows.Next() {
		item, err := scanSecurityEvent(rows)
		if err != nil {
			return SecurityEventPeriod{}, err
		}
		members = append(members, item)
	}
	if err := rows.Err(); err != nil {
		return SecurityEventPeriod{}, err
	}
	if len(members) == 0 {
		return SecurityEventPeriod{}, errNotFound
	}
	period := groupedSecurityPeriod(reqID, members, stats[reqID], ips[reqID], timeline[reqID])
	vectors, err := store.periodVectors(ctx, []string{reqID})
	if err != nil {
		return SecurityEventPeriod{}, err
	}
	period.Vectors = vectors[reqID]
	if title := multiAttackPeriodTitle(period.Vectors); title != "" {
		period.Title = title
	}
	if active, activeErr := store.periodActiveIPs(ctx, []string{reqID}); activeErr == nil {
		period.ActiveIPCount = active[reqID]
	}
	return period, nil
}

func (store *securityEventStore) periodStats(ctx context.Context, reqIDs []string) (map[string]securityPeriodStats, error) {
	out := map[string]securityPeriodStats{}
	if len(reqIDs) == 0 {
		return out, nil
	}
	placeholders := sqlPlaceholders(len(reqIDs))
	args := make([]any, len(reqIDs))
	for i, id := range reqIDs {
		args[i] = id
	}
	query := `
		SELECT req_id, COUNT(*), COUNT(DISTINCT NULLIF(source_ip, '')),
			MIN(created_at), MAX(created_at),
			MAX(NULLIF(attack_type, '')),
			MAX(CASE WHEN event_data = 'attack_start' THEN 1 ELSE 0 END),
			MAX(CASE WHEN event_data = 'attack_stop' THEN 1 ELSE 0 END)
		FROM security_events
		WHERE req_id IN (` + placeholders + `)
		GROUP BY req_id`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var reqID string
		var item securityPeriodStats
		var attack sql.NullString
		var startedHit, stoppedHit int
		if err := rows.Scan(&reqID, &item.eventCount, &item.ipCount, &item.started, &item.ended, &attack, &startedHit, &stoppedHit); err != nil {
			return nil, err
		}
		item.attackType = attack.String
		item.startedHit = startedHit == 1
		item.stoppedHit = stoppedHit == 1
		out[reqID] = item
	}
	return out, rows.Err()
}

func (store *securityEventStore) periodIPs(ctx context.Context, reqIDs []string, cap int) (map[string][]string, error) {
	out := map[string][]string{}
	if len(reqIDs) == 0 {
		return out, nil
	}
	if cap <= 0 {
		cap = 24
	}
	placeholders := sqlPlaceholders(len(reqIDs))
	args := make([]any, len(reqIDs))
	for i, id := range reqIDs {
		args[i] = id
	}
	query := `
		SELECT req_id, source_ip, MIN(created_at) AS first_at
		FROM security_events
		WHERE req_id IN (` + placeholders + `) AND source_ip <> ''
		GROUP BY req_id, source_ip
		ORDER BY req_id, first_at`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var reqID, ip string
		var first sql.NullTime
		if err := rows.Scan(&reqID, &ip, &first); err != nil {
			return nil, err
		}
		if len(out[reqID]) >= cap {
			continue
		}
		out[reqID] = append(out[reqID], ip)
	}
	return out, rows.Err()
}

func (store *securityEventStore) periodTimeline(ctx context.Context, reqIDs []string) (map[string][]SecurityEvent, error) {
	out := map[string][]SecurityEvent{}
	if len(reqIDs) == 0 {
		return out, nil
	}
	placeholders := sqlPlaceholders(len(reqIDs))
	args := make([]any, len(reqIDs))
	for i, id := range reqIDs {
		args[i] = id
	}
	query := `
		SELECT e.id, e.server_id, s.name, e.title, e.description, e.command, e.source_ip, e.ttl, e.attack_type, e.event_data, e.req_id, e.created_at, e.updated_at
		FROM security_events e
		LEFT JOIN servers s ON s.id = e.server_id
		WHERE e.req_id IN (` + placeholders + `) AND e.command <> 'report_block_ip'
		ORDER BY e.created_at ASC`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanSecurityEvent(rows)
		if err != nil {
			return nil, err
		}
		out[item.ReqID] = append(out[item.ReqID], item)
	}
	return out, rows.Err()
}

func scanSecurityEvent(rows *sql.Rows) (SecurityEvent, error) {
	var item SecurityEvent
	var serverID sql.NullInt64
	var serverName sql.NullString
	var createdAt sql.NullTime
	var updatedAt sql.NullTime
	err := rows.Scan(&item.ID, &serverID, &serverName, &item.Title, &item.Description, &item.Command, &item.SourceIP, &item.TTL, &item.AttackType, &item.Data, &item.ReqID, &createdAt, &updatedAt)
	if err != nil {
		return item, err
	}
	if serverID.Valid {
		value := serverID.Int64
		item.ServerID = &value
	}
	item.ServerName = serverName.String
	item.CreatedAt = formatTimestamp(createdAt)
	item.UpdatedAt = formatTimestamp(updatedAt)
	return item, nil
}

func singleSecurityPeriod(event SecurityEvent) SecurityEventPeriod {
	layer := periodLayer([]SecurityEvent{event})
	status := "reported"
	title := event.Title
	if event.AttackType != "" {
		if isL7AttackCommand(event.Command) {
			title = l7AttackPeriodTitle(event.AttackType)
		} else {
			title = attackPeriodTitle(event.AttackType)
		}
	}
	if !isAttackEvent(event) && !strings.Contains(strings.ToLower(event.Title), "ddos") {
		layer = ""
	}
	ipCount := 0
	if isL7AttackCommand(event.Command) {
		ipCount = atoiDefault(event.TTL, 0)
	}
	return SecurityEventPeriod{
		ID:          fmt.Sprintf("event:%d", event.ID),
		ServerID:    event.ServerID,
		ServerName:  event.ServerName,
		Layer:       layer,
		Title:       title,
		Description: event.Description,
		AttackType:  event.AttackType,
		Status:      status,
		StartedAt:   event.CreatedAt,
		CreatedAt:   event.CreatedAt,
		IPCount:     ipCount,
		EventCount:  1,
		Events:      []SecurityEvent{event},
	}
}

func groupedSecurityPeriod(reqID string, scanned []SecurityEvent, stats securityPeriodStats, ips []string, timeline []SecurityEvent) SecurityEventPeriod {
	latest := scanned[0]
	attackType := stats.attackType
	if attackType == "" {
		for _, event := range scanned {
			if event.AttackType != "" {
				attackType = event.AttackType
				break
			}
		}
	}
	status := "ongoing"
	if stats.stoppedHit || (stats.ended.Valid && time.Since(stats.ended.Time) > attackQuietTimeout) {
		status = "ended"
	}
	ipCount := stats.ipCount
	if ipCount == 0 {
		seen := map[string]struct{}{}
		for _, event := range scanned {
			if event.SourceIP == "" {
				continue
			}
			seen[event.SourceIP] = struct{}{}
		}
		ipCount = len(seen)
	}
	eventCount := stats.eventCount
	if eventCount == 0 {
		eventCount = len(scanned)
	}
	serverName := serverNames(scanned)
	if serverName == "" {
		serverName = latest.ServerName
	}
	started := formatTimestamp(stats.started)
	ended := formatTimestamp(stats.ended)
	if started == "" {
		started = latest.CreatedAt
	}
	if ended == "" {
		ended = latest.CreatedAt
	}
	layer := periodLayer(scanned)
	title := attackPeriodTitle(attackType)
	if layer == "L7" {
		title = l7AttackPeriodTitle(attackType)
		if ipCount == 0 {
			for i := len(scanned) - 1; i >= 0; i-- {
				if n := atoiDefault(scanned[i].TTL, 0); n > 0 {
					ipCount = n
					break
				}
			}
		}
	}
	if title == "" {
		title = latest.Title
	}
	if timeline == nil {
		timeline = []SecurityEvent{}
	}
	desc := periodDescription(ipCount, status)
	if layer == "L7" {
		desc = l7PeriodDescription(ipCount, status)
	}
	return SecurityEventPeriod{
		ID:           reqID,
		ReqID:        reqID,
		ServerID:     latest.ServerID,
		ServerName:   serverName,
		Layer:        layer,
		Title:        title,
		Description:  desc,
		AttackType:   attackType,
		Status:       status,
		StartedAt:    started,
		EndedAt:      ended,
		CreatedAt:    ended,
		BlockedIPs:   ips,
		IPCount:      ipCount,
		EventCount:   eventCount,
		StopReported: stats.stoppedHit,
		Events:       timeline,
	}
}

func l7PeriodDescription(ipCount int, status string) string {
	var summary string
	switch {
	case ipCount == 1:
		summary = "1 unique IP"
	case ipCount > 1:
		summary = fmt.Sprintf("%d unique IPs", ipCount)
	case status == "ended":
		summary = "Attack ended"
	default:
		summary = "Attack in progress"
	}
	switch status {
	case "ongoing":
		if ipCount > 0 {
			summary += " · Ongoing"
		}
	case "ended":
		if ipCount > 0 {
			summary += " · Ended"
		}
	}
	return summary
}

func l7AttackPeriodTitle(attackType string) string {
	parts := strings.FieldsFunc(attackType, func(r rune) bool {
		return r == '+' || r == ',' || r == '|' || r == '/'
	})
	labels := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		label := L7VectorLabel(part)
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		labels = append(labels, label)
	}
	switch len(labels) {
	case 0:
		return "L7 attack"
	case 1:
		return labels[0] + " attack"
	case 2:
		return labels[0] + " + " + labels[1] + " attack"
	default:
		return strings.Join(labels[:len(labels)-1], ", ") + " + " + labels[len(labels)-1] + " attack"
	}
}

func atoiDefault(raw string, fallback int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	var n int
	for _, r := range raw {
		if r < '0' || r > '9' {
			return fallback
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func periodDescription(ipCount int, status string) string {
	var summary string
	switch {
	case ipCount == 1:
		summary = "1 source IP blocked"
	case ipCount > 1:
		summary = fmt.Sprintf("%d source IPs blocked", ipCount)
	case status == "ended":
		summary = "Attack ended"
	default:
		summary = "Attack in progress"
	}
	switch status {
	case "ongoing":
		if ipCount > 0 {
			summary += " · Ongoing"
		}
	case "ended":
		if ipCount > 0 {
			summary += " · Ended"
		}
	}
	return summary
}

func attackPeriodTitle(attackType string) string {
	label := strings.TrimSpace(attackType)
	if label == "" {
		return ""
	}
	if mapped := periodVectorLabel(label); mapped != "" {
		return mapped + " flood"
	}
	if strings.Contains(strings.ToLower(label), "attack") {
		return label
	}
	if !strings.Contains(label, " ") && len(label) <= 8 {
		return strings.ToUpper(label) + " attack"
	}
	return label + " attack"
}

func multiAttackPeriodTitle(vectors []PeriodVector) string {
	labels := make([]string, 0, len(vectors))
	seen := map[string]struct{}{}
	for _, item := range vectors {
		label := strings.TrimSpace(item.Type)
		if label == "" {
			continue
		}
		if mapped := periodVectorLabel(label); mapped != "" {
			label = mapped
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		labels = append(labels, label)
	}
	switch len(labels) {
	case 0:
		return ""
	case 1:
		return labels[0] + " flood"
	case 2:
		return labels[0] + " + " + labels[1] + " flood"
	default:
		return strings.Join(labels[:len(labels)-1], ", ") + " + " + labels[len(labels)-1] + " flood"
	}
}

func serverNames(events []SecurityEvent) string {
	seen := map[string]struct{}{}
	names := make([]string, 0, 2)
	for _, event := range events {
		name := strings.TrimSpace(event.ServerName)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

func isAttackEvent(event SecurityEvent) bool {
	command := strings.ToLower(event.Command)
	return command == "report_attack" || command == "report_l7_attack" || command == "report_block_ip" || event.AttackType != ""
}

func isL7AttackCommand(command string) bool {
	return strings.EqualFold(strings.TrimSpace(command), "report_l7_attack")
}

func periodLayer(events []SecurityEvent) string {
	for _, event := range events {
		if isL7AttackCommand(event.Command) {
			return "L7"
		}
		if strings.EqualFold(event.Command, "report_attack") || strings.EqualFold(event.Command, "report_block_ip") {
			return "L4"
		}
	}
	return "L4"
}

func sqlPlaceholders(count int) string {
	parts := make([]string, count)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}
