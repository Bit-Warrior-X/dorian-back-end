package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// L7GuardSettings is the effective per-edge L7 abuse detector configuration.
// JSON uses snake_case to match Angelos; Unmarshal also accepts camelCase aliases.
type L7GuardSettings struct {
	Enabled       bool     `json:"enabled"`
	XDP           bool     `json:"xdp"`
	Window        int      `json:"window"`
	RSTThreshold  int      `json:"rst_threshold"`
	RejThreshold  int      `json:"rej_threshold"`
	BadThreshold  int      `json:"bad_threshold"`
	ReqThreshold  int      `json:"req_threshold"`
	BlockTTL      int      `json:"block_ttl"`
	BlockMaxTTL   int      `json:"block_max_ttl"`
	AllowIPs      []string `json:"allow_ips"`
}

type L7GuardState struct {
	Status    string          `json:"status,omitempty"`
	ServerID  int64           `json:"serverId,omitempty"`
	L7Guard   L7GuardSettings `json:"l7guard"`
	Overrides map[string]any  `json:"overrides,omitempty"`
	Defaults  L7GuardSettings `json:"defaults"`
}

type L7GuardStore interface {
	EnsureSchema(ctx context.Context) error
	Get(ctx context.Context, serverID int64) (L7GuardState, error)
	Upsert(ctx context.Context, serverID int64, settings L7GuardSettings) (L7GuardState, error)
	Reset(ctx context.Context, serverID int64) (L7GuardState, error)
}

type l7GuardStore struct {
	db *sql.DB
}

func NewL7GuardStore(db *sql.DB) L7GuardStore {
	return &l7GuardStore{db: db}
}

func DefaultL7GuardSettings() L7GuardSettings {
	return L7GuardSettings{
		Enabled:      true,
		XDP:          true,
		Window:       10,
		RSTThreshold: 100,
		RejThreshold: 200,
		BadThreshold: 100,
		ReqThreshold: 1000,
		BlockTTL:     600,
		BlockMaxTTL:  3600,
		AllowIPs:     []string{},
	}
}

func (store *l7GuardStore) EnsureSchema(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS l7_guard_settings (
			server_id BIGINT NOT NULL,
			settings_json JSON NOT NULL,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (server_id),
			CONSTRAINT l7_guard_settings_server_fk
				FOREIGN KEY (server_id) REFERENCES servers (id)
				ON DELETE CASCADE ON UPDATE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
	return err
}

func (store *l7GuardStore) Get(ctx context.Context, serverID int64) (L7GuardState, error) {
	defaults := DefaultL7GuardSettings()
	state := L7GuardState{
		Status:   "success",
		ServerID: serverID,
		L7Guard:  defaults,
		Defaults: defaults,
	}
	if serverID <= 0 {
		return state, fmt.Errorf("invalid server id")
	}
	var raw []byte
	err := store.db.QueryRowContext(ctx, `
		SELECT settings_json FROM l7_guard_settings WHERE server_id = ?`, serverID).Scan(&raw)
	if err == sql.ErrNoRows {
		state.Overrides = map[string]any{}
		return state, nil
	}
	if err != nil {
		return state, err
	}
	stored, err := DecodeL7GuardSettings(raw)
	if err != nil {
		return state, err
	}
	state.L7Guard = MergeL7GuardSettings(defaults, stored)
	state.Overrides = DiffL7GuardOverrides(defaults, stored)
	return state, nil
}

func (store *l7GuardStore) Upsert(ctx context.Context, serverID int64, settings L7GuardSettings) (L7GuardState, error) {
	defaults := DefaultL7GuardSettings()
	normalized, err := NormalizeL7GuardSettings(settings)
	if err != nil {
		return L7GuardState{}, err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return L7GuardState{}, err
	}
	_, err = store.db.ExecContext(ctx, `
		INSERT INTO l7_guard_settings (server_id, settings_json, updated_at)
		VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE settings_json = VALUES(settings_json), updated_at = VALUES(updated_at)`,
		serverID, raw, time.Now().UTC())
	if err != nil {
		return L7GuardState{}, err
	}
	return L7GuardState{
		Status:    "success",
		ServerID:  serverID,
		L7Guard:   normalized,
		Overrides: DiffL7GuardOverrides(defaults, normalized),
		Defaults:  defaults,
	}, nil
}

func (store *l7GuardStore) Reset(ctx context.Context, serverID int64) (L7GuardState, error) {
	if serverID <= 0 {
		return L7GuardState{}, fmt.Errorf("invalid server id")
	}
	_, err := store.db.ExecContext(ctx, `DELETE FROM l7_guard_settings WHERE server_id = ?`, serverID)
	if err != nil {
		return L7GuardState{}, err
	}
	defaults := DefaultL7GuardSettings()
	return L7GuardState{
		Status:    "success",
		ServerID:  serverID,
		L7Guard:   defaults,
		Overrides: map[string]any{},
		Defaults:  defaults,
	}, nil
}

func DecodeL7GuardSettings(raw []byte) (L7GuardSettings, error) {
	out := DefaultL7GuardSettings()
	if len(raw) == 0 {
		return out, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return out, err
	}
	applyL7GuardMap(&out, payload)
	return NormalizeL7GuardSettings(out)
}

func MergeL7GuardSettings(defaults, overrides L7GuardSettings) L7GuardSettings {
	merged := defaults
	// Full object replace semantics for stored rows: stored already contains all fields.
	merged = overrides
	if merged.AllowIPs == nil {
		merged.AllowIPs = []string{}
	}
	normalized, err := NormalizeL7GuardSettings(merged)
	if err != nil {
		return defaults
	}
	return normalized
}

func DiffL7GuardOverrides(defaults, effective L7GuardSettings) map[string]any {
	out := map[string]any{}
	if effective.Enabled != defaults.Enabled {
		out["enabled"] = effective.Enabled
	}
	if effective.XDP != defaults.XDP {
		out["xdp"] = effective.XDP
	}
	if effective.Window != defaults.Window {
		out["window"] = effective.Window
	}
	if effective.RSTThreshold != defaults.RSTThreshold {
		out["rst_threshold"] = effective.RSTThreshold
	}
	if effective.RejThreshold != defaults.RejThreshold {
		out["rej_threshold"] = effective.RejThreshold
	}
	if effective.BadThreshold != defaults.BadThreshold {
		out["bad_threshold"] = effective.BadThreshold
	}
	if effective.ReqThreshold != defaults.ReqThreshold {
		out["req_threshold"] = effective.ReqThreshold
	}
	if effective.BlockTTL != defaults.BlockTTL {
		out["block_ttl"] = effective.BlockTTL
	}
	if effective.BlockMaxTTL != defaults.BlockMaxTTL {
		out["block_max_ttl"] = effective.BlockMaxTTL
	}
	if !sameStringSlice(effective.AllowIPs, defaults.AllowIPs) {
		out["allow_ips"] = append([]string{}, effective.AllowIPs...)
	}
	return out
}

func NormalizeL7GuardSettings(in L7GuardSettings) (L7GuardSettings, error) {
	out := in
	if out.Window < 1 || out.Window > 300 {
		return out, fmt.Errorf("window must be between 1 and 300")
	}
	if out.RSTThreshold < 1 || out.RSTThreshold > 1_000_000 {
		return out, fmt.Errorf("rst_threshold must be between 1 and 1000000")
	}
	if out.RejThreshold < 1 || out.RejThreshold > 1_000_000 {
		return out, fmt.Errorf("rej_threshold must be between 1 and 1000000")
	}
	if out.BadThreshold < 1 || out.BadThreshold > 1_000_000 {
		return out, fmt.Errorf("bad_threshold must be between 1 and 1000000")
	}
	if out.ReqThreshold < 1 || out.ReqThreshold > 1_000_000 {
		return out, fmt.Errorf("req_threshold must be between 1 and 1000000")
	}
	if out.BlockTTL < 10 || out.BlockTTL > 86400 {
		return out, fmt.Errorf("block_ttl must be between 10 and 86400")
	}
	if out.BlockMaxTTL < 10 || out.BlockMaxTTL > 604800 {
		return out, fmt.Errorf("block_max_ttl must be between 10 and 604800")
	}
	if out.BlockMaxTTL < out.BlockTTL {
		return out, fmt.Errorf("block_max_ttl must be greater than or equal to block_ttl")
	}
	ips, err := normalizeAllowIPs(out.AllowIPs)
	if err != nil {
		return out, err
	}
	out.AllowIPs = ips
	return out, nil
}

func normalizeAllowIPs(values []string) ([]string, error) {
	if len(values) == 0 {
		return []string{}, nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		if strings.Contains(ip, "/") {
			return nil, fmt.Errorf("allow_ips must be single IPv4 addresses (no CIDR): %s", ip)
		}
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil {
			return nil, fmt.Errorf("allow_ips contains invalid IPv4 address: %s", ip)
		}
		canon := parsed.To4().String()
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon)
		if len(out) > 1000 {
			return nil, fmt.Errorf("allow_ips supports at most 1000 addresses")
		}
	}
	sort.Strings(out)
	return out, nil
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func applyL7GuardMap(dst *L7GuardSettings, payload map[string]any) {
	if payload == nil {
		return
	}
	if v, ok := boolFromAny(payload["enabled"]); ok {
		dst.Enabled = v
	}
	if raw, ok := firstMapValue(payload, "xdp", "xdpEscalation"); ok {
		if v, ok := boolFromAny(raw); ok {
			dst.XDP = v
		}
	}
	if raw, ok := firstMapValue(payload, "window", "windowSeconds"); ok {
		if v, ok := intFromAny(raw); ok {
			dst.Window = v
		}
	}
	if raw, ok := firstMapValue(payload, "rst_threshold", "rstThreshold"); ok {
		if v, ok := intFromAny(raw); ok {
			dst.RSTThreshold = v
		}
	}
	if raw, ok := firstMapValue(payload, "rej_threshold", "rejThreshold"); ok {
		if v, ok := intFromAny(raw); ok {
			dst.RejThreshold = v
		}
	}
	if raw, ok := firstMapValue(payload, "bad_threshold", "badThreshold"); ok {
		if v, ok := intFromAny(raw); ok {
			dst.BadThreshold = v
		}
	}
	if raw, ok := firstMapValue(payload, "req_threshold", "reqThreshold"); ok {
		if v, ok := intFromAny(raw); ok {
			dst.ReqThreshold = v
		}
	}
	if raw, ok := firstMapValue(payload, "block_ttl", "blockTtl", "blockTTL"); ok {
		if v, ok := intFromAny(raw); ok {
			dst.BlockTTL = v
		}
	}
	if raw, ok := firstMapValue(payload, "block_max_ttl", "blockMaxTtl", "blockMaxTTL"); ok {
		if v, ok := intFromAny(raw); ok {
			dst.BlockMaxTTL = v
		}
	}
	if raw, ok := firstMapValue(payload, "allow_ips", "allowIps"); ok {
		dst.AllowIPs = stringSliceFromAny(raw)
	}
}

func firstMapValue(payload map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func boolFromAny(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "true", "yes", "on":
			return true, true
		case "0", "false", "no", "off":
			return false, true
		}
	case float64:
		return typed != 0, true
	case int:
		return typed != 0, true
	case int64:
		return typed != 0, true
	case json.Number:
		n, err := typed.Int64()
		if err != nil {
			return false, false
		}
		return n != 0, true
	}
	return false, false
}

func intFromAny(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), true
	case float32:
		return int(typed), true
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case json.Number:
		n, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	case string:
		n, err := json.Number(strings.TrimSpace(typed)).Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

func stringSliceFromAny(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string{}, typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, strings.TrimSpace(fmt.Sprint(item)))
		}
		return out
	case string:
		parts := strings.FieldsFunc(typed, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\n' || r == '\t'
		})
		return parts
	default:
		return nil
	}
}
