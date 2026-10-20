package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	SettingRequireMFA = "security.require_mfa"

	RequireMFAOff    = "off"
	RequireMFAAdmins = "admins"
	RequireMFAAll    = "all"
)

func NormalizeRequireMFA(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case RequireMFAAdmins:
		return RequireMFAAdmins
	case RequireMFAAll:
		return RequireMFAAll
	default:
		return RequireMFAOff
	}
}

// RequireMFAApplies reports whether the policy forces 2FA for this role.
func RequireMFAApplies(policy, role string) bool {
	switch NormalizeRequireMFA(policy) {
	case RequireMFAAll:
		return true
	case RequireMFAAdmins:
		return strings.EqualFold(strings.TrimSpace(role), "Admin")
	default:
		return false
	}
}

type PanelSettingsStore interface {
	EnsureSchema(ctx context.Context) error
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, updatedBy int64) error
}

const panelSettingsCacheTTL = 15 * time.Second

type panelSettingsStore struct {
	db *sql.DB

	mu     sync.Mutex
	cache  map[string]string
	loaded time.Time
}

func NewPanelSettingsStore(db *sql.DB) PanelSettingsStore {
	return &panelSettingsStore{db: db}
}

func (store *panelSettingsStore) EnsureSchema(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS panel_settings (
			setting_key VARCHAR(64) NOT NULL,
			setting_value TEXT NOT NULL,
			updated_by BIGINT(20) DEFAULT NULL,
			updated_at DATETIME NOT NULL,
			PRIMARY KEY (setting_key)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
	return err
}

// Get reads through a short in-process cache because the auth middleware asks
// for the 2FA policy on every request.
func (store *panelSettingsStore) Get(ctx context.Context, key string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.cache == nil || time.Since(store.loaded) > panelSettingsCacheTTL {
		rows, err := store.db.QueryContext(ctx, `SELECT setting_key, setting_value FROM panel_settings`)
		if err != nil {
			if store.cache != nil {
				return store.cache[key], nil
			}
			return "", err
		}
		next := make(map[string]string)
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				rows.Close()
				return "", err
			}
			next[k] = v
		}
		rows.Close()
		store.cache = next
		store.loaded = time.Now()
	}
	return store.cache[key], nil
}

func (store *panelSettingsStore) Set(ctx context.Context, key, value string, updatedBy int64) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("setting key is required")
	}
	var by any
	if updatedBy > 0 {
		by = updatedBy
	}
	_, err := store.db.ExecContext(ctx, `
		INSERT INTO panel_settings (setting_key, setting_value, updated_by, updated_at)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)`,
		key, value, by, time.Now().UTC())
	if err != nil {
		return err
	}
	store.mu.Lock()
	if store.cache != nil {
		store.cache[key] = value
	}
	store.mu.Unlock()
	return nil
}
