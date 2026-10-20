package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

type AuthSession struct {
	ID         string     `json:"id"`
	UserID     int64      `json:"userId"`
	Method     string     `json:"method"`
	Remember   bool       `json:"remember"`
	IPAddress  string     `json:"ipAddress"`
	UserAgent  string     `json:"userAgent"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastSeenAt time.Time  `json:"lastSeenAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

type AuthSessionCreateInput struct {
	UserID    int64
	Method    string
	Remember  bool
	IPAddress string
	UserAgent string
	TTL       time.Duration
}

// AuthSessionLookup is the per-request view of a session: the user's current
// role and status come from the users table, never from the JWT.
type AuthSessionLookup struct {
	Session    AuthSession
	UserID     int64
	Name       string
	Email      string
	Role       string
	Status     string
	MFAEnabled bool
}

type AuthSessionStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, input AuthSessionCreateInput) (AuthSession, error)
	LookupActive(ctx context.Context, id string) (AuthSessionLookup, error)
	Touch(ctx context.Context, id string) error
	ListActiveForUser(ctx context.Context, userID int64) ([]AuthSession, error)
	Revoke(ctx context.Context, userID int64, id string) (bool, error)
	RevokeAllForUser(ctx context.Context, userID int64, exceptID string) (int64, error)
	LastSignIns(ctx context.Context) (map[int64]time.Time, error)
}

const authSessionTouchInterval = time.Minute

type authSessionStore struct {
	db *sql.DB
}

func NewAuthSessionStore(db *sql.DB) AuthSessionStore {
	return &authSessionStore{db: db}
}

func (store *authSessionStore) EnsureSchema(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS user_sessions (
			id VARCHAR(64) NOT NULL,
			user_id BIGINT(20) NOT NULL,
			auth_method VARCHAR(32) NOT NULL DEFAULT 'password',
			remember TINYINT(1) NOT NULL DEFAULT 0,
			ip_address VARCHAR(64) NOT NULL DEFAULT '',
			user_agent VARCHAR(512) NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL,
			last_seen_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME DEFAULT NULL,
			PRIMARY KEY (id),
			KEY idx_user_sessions_user (user_id, revoked_at, expires_at),
			CONSTRAINT fk_user_sessions_user
				FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
	return err
}

func newSessionID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func truncateRunes(value string, max int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max])
}

func (store *authSessionStore) Create(ctx context.Context, input AuthSessionCreateInput) (AuthSession, error) {
	if input.UserID <= 0 {
		return AuthSession{}, errors.New("user id is required")
	}
	if input.TTL <= 0 {
		input.TTL = 24 * time.Hour
	}
	id, err := newSessionID()
	if err != nil {
		return AuthSession{}, err
	}
	method := strings.ToLower(strings.TrimSpace(input.Method))
	if method == "" {
		method = "password"
	}
	now := time.Now().UTC().Truncate(time.Second)
	session := AuthSession{
		ID:         id,
		UserID:     input.UserID,
		Method:     truncateRunes(method, 32),
		Remember:   input.Remember,
		IPAddress:  truncateRunes(input.IPAddress, 64),
		UserAgent:  truncateRunes(input.UserAgent, 512),
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(input.TTL),
	}
	_, err = store.db.ExecContext(ctx, `
		INSERT INTO user_sessions (id, user_id, auth_method, remember, ip_address, user_agent, created_at, last_seen_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.UserID, session.Method, session.Remember, session.IPAddress, session.UserAgent,
		session.CreatedAt, session.LastSeenAt, session.ExpiresAt)
	if err != nil {
		return AuthSession{}, err
	}
	return session, nil
}

func (store *authSessionStore) LookupActive(ctx context.Context, id string) (AuthSessionLookup, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return AuthSessionLookup{}, errNotFound
	}
	var out AuthSessionLookup
	var revokedAt sql.NullTime
	var totpEnabledAt sql.NullTime
	err := store.db.QueryRowContext(ctx, `
		SELECT s.id, s.user_id, s.auth_method, s.remember, s.ip_address, s.user_agent,
		       s.created_at, s.last_seen_at, s.expires_at, s.revoked_at,
		       u.name, u.email, u.role, u.status, u.totp_enabled_at
		FROM user_sessions s
		INNER JOIN users u ON u.id = s.user_id
		WHERE s.id = ?`, id).Scan(
		&out.Session.ID, &out.Session.UserID, &out.Session.Method, &out.Session.Remember,
		&out.Session.IPAddress, &out.Session.UserAgent,
		&out.Session.CreatedAt, &out.Session.LastSeenAt, &out.Session.ExpiresAt, &revokedAt,
		&out.Name, &out.Email, &out.Role, &out.Status, &totpEnabledAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthSessionLookup{}, errNotFound
		}
		return AuthSessionLookup{}, err
	}
	if revokedAt.Valid || !out.Session.ExpiresAt.After(time.Now().UTC()) {
		return AuthSessionLookup{}, errNotFound
	}
	out.UserID = out.Session.UserID
	out.MFAEnabled = totpEnabledAt.Valid
	return out, nil
}

func (store *authSessionStore) Touch(ctx context.Context, id string) error {
	now := time.Now().UTC().Truncate(time.Second)
	_, err := store.db.ExecContext(ctx, `
		UPDATE user_sessions SET last_seen_at = ?
		WHERE id = ? AND last_seen_at < ?`,
		now, id, now.Add(-authSessionTouchInterval))
	return err
}

func (store *authSessionStore) ListActiveForUser(ctx context.Context, userID int64) ([]AuthSession, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, user_id, auth_method, remember, ip_address, user_agent, created_at, last_seen_at, expires_at
		FROM user_sessions
		WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
		ORDER BY last_seen_at DESC`, userID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AuthSession, 0)
	for rows.Next() {
		var item AuthSession
		if err := rows.Scan(&item.ID, &item.UserID, &item.Method, &item.Remember, &item.IPAddress, &item.UserAgent,
			&item.CreatedAt, &item.LastSeenAt, &item.ExpiresAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (store *authSessionStore) Revoke(ctx context.Context, userID int64, id string) (bool, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE user_sessions SET revoked_at = ?
		WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), strings.TrimSpace(id), userID)
	if err != nil {
		return false, err
	}
	affected, _ := result.RowsAffected()
	return affected > 0, nil
}

func (store *authSessionStore) RevokeAllForUser(ctx context.Context, userID int64, exceptID string) (int64, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE user_sessions SET revoked_at = ?
		WHERE user_id = ? AND revoked_at IS NULL AND id <> ?`,
		time.Now().UTC(), userID, strings.TrimSpace(exceptID))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (store *authSessionStore) LastSignIns(ctx context.Context) (map[int64]time.Time, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT user_id, MAX(signed_in_at) FROM (
			SELECT user_id, created_at AS signed_in_at FROM user_sessions
			UNION ALL
			SELECT actor_user_id, created_at FROM audit_logs
			WHERE action = 'login' AND actor_user_id IS NOT NULL AND actor_user_id > 0
		) AS sign_ins
		GROUP BY user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[int64]time.Time)
	for rows.Next() {
		var userID int64
		var at time.Time
		if err := rows.Scan(&userID, &at); err != nil {
			return nil, err
		}
		out[userID] = at
	}
	return out, rows.Err()
}
