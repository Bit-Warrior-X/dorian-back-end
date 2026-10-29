package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// L7AttackIncident is the full edge incident snapshot from report_l7_attack / GET APIs.
// Request outcomes are exclusive: requests = passed + blocked + malformed + rapid_reset.
// Incidents carry request counts (not bandwidth).
type L7AttackIncident struct {
	ID               string           `json:"id"`
	Status           string           `json:"status"`
	StartedAt        int64            `json:"started_at"`
	EndedAt          *int64           `json:"ended_at,omitempty"`
	UpdatedAt        int64            `json:"updated_at,omitempty"`
	Duration         int              `json:"duration,omitempty"`
	VectorList       []string         `json:"vector_list,omitempty"`
	Vectors          map[string]any   `json:"vectors,omitempty"`
	PeakRPS          int              `json:"peak_rps,omitempty"`
	PeakRPSAt        int64            `json:"peak_rps_at,omitempty"`
	PeakBlockedRPS   int              `json:"peak_blocked_rps,omitempty"`
	PeakBlockedRPSAt int64            `json:"peak_blocked_rps_at,omitempty"`
	PeakPassedRPS    int              `json:"peak_passed_rps,omitempty"`
	PeakPassedRPSAt  int64            `json:"peak_passed_rps_at,omitempty"`
	BlockedRatio     float64          `json:"blocked_ratio,omitempty"`
	BlockedIPs       int              `json:"blocked_ips,omitempty"`
	Totals           map[string]any   `json:"totals,omitempty"`
	UniqueIPs        int              `json:"unique_ips,omitempty"`
	Sampling         map[string]any   `json:"sampling,omitempty"`
	TopIPs           []map[string]any `json:"top_ips,omitempty"`
	TopURLs          []map[string]any `json:"top_urls,omitempty"`
	TopUserAgents    []map[string]any `json:"top_user_agents,omitempty"`
	TopCountries     []map[string]any `json:"top_countries,omitempty"`
	StatusCodes      map[string]any   `json:"status_codes,omitempty"`
	Protocols        map[string]any   `json:"protocols,omitempty"`
	Methods          map[string]any   `json:"methods,omitempty"`
	BlockRules       map[string]any   `json:"block_rules,omitempty"`
	Sites            []map[string]any `json:"sites,omitempty"`
	Escalations      map[string]any   `json:"escalations,omitempty"`
	Timeline         []map[string]any `json:"timeline,omitempty"`
	Detector         map[string]any   `json:"detector,omitempty"`
}

type L7AttackRecord struct {
	ServerID       int64            `json:"serverId"`
	ReqID          string           `json:"reqId"`
	Status         string           `json:"status"`
	StartedAt      time.Time        `json:"startedAt"`
	EndedAt        *time.Time       `json:"endedAt,omitempty"`
	UpdatedAt      time.Time        `json:"updatedAt"`
	PeakRPS        int              `json:"peakRps"`
	TotalRequests  int              `json:"totalRequests"`
	UniqueIPs      int              `json:"uniqueIps"`
	Vectors        []string         `json:"vectors"`
	LastData       string           `json:"lastData"`
	Incident       L7AttackIncident `json:"incident"`
}

type L7AttackStore interface {
	EnsureSchema(ctx context.Context) error
	Upsert(ctx context.Context, serverID int64, data string, incident L7AttackIncident) (L7AttackRecord, error)
	Get(ctx context.Context, reqID string) (L7AttackRecord, error)
	GetByServer(ctx context.Context, serverID int64, reqID string) (L7AttackRecord, error)
}

type l7AttackStore struct {
	db *sql.DB
}

func NewL7AttackStore(db *sql.DB) L7AttackStore {
	return &l7AttackStore{db: db}
}

func (store *l7AttackStore) EnsureSchema(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS l7_attacks (
			req_id VARCHAR(64) NOT NULL,
			server_id BIGINT NOT NULL,
			status VARCHAR(16) NOT NULL DEFAULT 'active',
			started_at TIMESTAMP NOT NULL,
			ended_at TIMESTAMP NULL,
			updated_at TIMESTAMP NOT NULL,
			peak_rps INT NOT NULL DEFAULT 0,
			total_requests BIGINT NOT NULL DEFAULT 0,
			unique_ips INT NOT NULL DEFAULT 0,
			vectors_json JSON NOT NULL,
			last_data VARCHAR(32) NOT NULL DEFAULT '',
			incident_json LONGTEXT NOT NULL,
			PRIMARY KEY (req_id),
			KEY l7_attacks_server_started (server_id, started_at),
			KEY l7_attacks_status_updated (status, updated_at),
			CONSTRAINT l7_attacks_server_fk
				FOREIGN KEY (server_id) REFERENCES servers (id)
				ON DELETE CASCADE ON UPDATE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
	return err
}

func (store *l7AttackStore) Upsert(ctx context.Context, serverID int64, data string, incident L7AttackIncident) (L7AttackRecord, error) {
	reqID := strings.TrimSpace(incident.ID)
	if serverID <= 0 || reqID == "" {
		return L7AttackRecord{}, fmt.Errorf("invalid l7 attack identity")
	}
	data = strings.ToLower(strings.TrimSpace(data))
	status := strings.ToLower(strings.TrimSpace(incident.Status))
	if status == "" {
		if data == "attack_stop" {
			status = "ended"
		} else {
			status = "active"
		}
	}
	if data == "attack_stop" {
		status = "ended"
	}

	startedAt := unixToTime(incident.StartedAt)
	updatedAt := unixToTime(incident.UpdatedAt)
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	var endedAt *time.Time
	if incident.EndedAt != nil && *incident.EndedAt > 0 {
		t := unixToTime(*incident.EndedAt)
		endedAt = &t
	} else if status == "ended" {
		t := updatedAt
		endedAt = &t
		v := t.Unix()
		incident.EndedAt = &v
	}
	incident.ID = reqID
	incident.Status = status

	vectors := append([]string{}, incident.VectorList...)
	if len(vectors) == 0 && incident.Vectors != nil {
		for key := range incident.Vectors {
			vectors = append(vectors, key)
		}
	}
	vectorsJSON, err := json.Marshal(vectors)
	if err != nil {
		return L7AttackRecord{}, err
	}
	incidentJSON, err := json.Marshal(incident)
	if err != nil {
		return L7AttackRecord{}, err
	}

	totalRequests := 0
	if incident.Totals != nil {
		totalRequests = intFromMap(incident.Totals, "requests")
	}
	uniqueIPs := incident.UniqueIPs
	peakRPS := incident.PeakRPS

	_, err = store.db.ExecContext(ctx, `
		INSERT INTO l7_attacks (
			req_id, server_id, status, started_at, ended_at, updated_at,
			peak_rps, total_requests, unique_ips, vectors_json, last_data, incident_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			server_id = VALUES(server_id),
			status = VALUES(status),
			started_at = LEAST(started_at, VALUES(started_at)),
			ended_at = VALUES(ended_at),
			updated_at = VALUES(updated_at),
			peak_rps = GREATEST(peak_rps, VALUES(peak_rps)),
			total_requests = VALUES(total_requests),
			unique_ips = VALUES(unique_ips),
			vectors_json = VALUES(vectors_json),
			last_data = VALUES(last_data),
			incident_json = VALUES(incident_json)`,
		reqID, serverID, status, startedAt, endedAt, updatedAt,
		peakRPS, totalRequests, uniqueIPs, vectorsJSON, data, incidentJSON,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return L7AttackRecord{}, errNotFound
		}
		return L7AttackRecord{}, err
	}
	return store.Get(ctx, reqID)
}

func (store *l7AttackStore) Get(ctx context.Context, reqID string) (L7AttackRecord, error) {
	reqID = strings.TrimSpace(reqID)
	if reqID == "" {
		return L7AttackRecord{}, errNotFound
	}
	return store.scanOne(ctx, `
		SELECT req_id, server_id, status, started_at, ended_at, updated_at,
			peak_rps, total_requests, unique_ips, vectors_json, last_data, incident_json
		FROM l7_attacks WHERE req_id = ?`, reqID)
}

func (store *l7AttackStore) GetByServer(ctx context.Context, serverID int64, reqID string) (L7AttackRecord, error) {
	reqID = strings.TrimSpace(reqID)
	if serverID <= 0 || reqID == "" {
		return L7AttackRecord{}, errNotFound
	}
	return store.scanOne(ctx, `
		SELECT req_id, server_id, status, started_at, ended_at, updated_at,
			peak_rps, total_requests, unique_ips, vectors_json, last_data, incident_json
		FROM l7_attacks WHERE req_id = ? AND server_id = ?`, reqID, serverID)
}

func (store *l7AttackStore) scanOne(ctx context.Context, query string, args ...any) (L7AttackRecord, error) {
	var (
		rec          L7AttackRecord
		started      time.Time
		ended        sql.NullTime
		updated      time.Time
		vectorsRaw   []byte
		incidentRaw  []byte
		totalRequests int64
	)
	err := store.db.QueryRowContext(ctx, query, args...).Scan(
		&rec.ReqID, &rec.ServerID, &rec.Status, &started, &ended, &updated,
		&rec.PeakRPS, &totalRequests, &rec.UniqueIPs, &vectorsRaw, &rec.LastData, &incidentRaw,
	)
	if err == sql.ErrNoRows {
		return L7AttackRecord{}, errNotFound
	}
	if err != nil {
		return L7AttackRecord{}, err
	}
	rec.StartedAt = started.UTC()
	rec.UpdatedAt = updated.UTC()
	if ended.Valid {
		t := ended.Time.UTC()
		rec.EndedAt = &t
	}
	rec.TotalRequests = int(totalRequests)
	_ = json.Unmarshal(vectorsRaw, &rec.Vectors)
	if rec.Vectors == nil {
		rec.Vectors = []string{}
	}
	_ = json.Unmarshal(incidentRaw, &rec.Incident)
	if rec.Incident.ID == "" {
		rec.Incident.ID = rec.ReqID
	}
	return rec, nil
}

func unixToTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

func intFromMap(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	v, ok := intFromAny(m[key])
	if !ok {
		return 0
	}
	return v
}

// L7VectorLabel maps edge vector ids to short UI labels.
func L7VectorLabel(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "flood":
		return "Flood"
	case "rapid_reset", "rapid-reset", "rapidreset":
		return "Rapid Reset"
	case "malformed":
		return "Malformed"
	case "blocked":
		return "Blocked"
	default:
		return strings.TrimSpace(raw)
	}
}
