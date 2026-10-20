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

const (
	UserTokenInvite        = "invite"
	UserTokenPasswordReset = "reset"
)

// UserTokenPeek describes a one-time link without consuming it, so the
// landing page can greet the user before they choose a password.
type UserTokenPeek struct {
	UserID    int64     `json:"-"`
	Purpose   string    `json:"purpose"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type UserTokenStore interface {
	EnsureSchema(ctx context.Context) error
	// Issue invalidates earlier unused links of the same purpose for the user.
	Issue(ctx context.Context, userID int64, purpose string, ttl time.Duration, createdBy int64) (string, time.Time, error)
	Peek(ctx context.Context, secret, purpose string) (UserTokenPeek, error)
	Consume(ctx context.Context, secret, purpose string) (UserTokenPeek, error)
}

type userTokenStore struct {
	db *sql.DB
}

func NewUserTokenStore(db *sql.DB) UserTokenStore {
	return &userTokenStore{db: db}
}

func (store *userTokenStore) EnsureSchema(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS user_tokens (
			id BIGINT(20) NOT NULL AUTO_INCREMENT,
			user_id BIGINT(20) NOT NULL,
			purpose VARCHAR(16) NOT NULL,
			token_hash CHAR(64) NOT NULL,
			created_by BIGINT(20) DEFAULT NULL,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			used_at DATETIME DEFAULT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY uq_user_tokens_hash (token_hash),
			KEY idx_user_tokens_user (user_id, purpose, used_at),
			CONSTRAINT fk_user_tokens_user
				FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
	return err
}

func validUserTokenPurpose(purpose string) bool {
	return purpose == UserTokenInvite || purpose == UserTokenPasswordReset
}

func (store *userTokenStore) Issue(ctx context.Context, userID int64, purpose string, ttl time.Duration, createdBy int64) (string, time.Time, error) {
	if userID <= 0 || !validUserTokenPurpose(purpose) {
		return "", time.Time{}, errors.New("invalid token request")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(ttl)

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE user_tokens SET used_at = ?
		WHERE user_id = ? AND purpose = ? AND used_at IS NULL`, now, userID, purpose); err != nil {
		return "", time.Time{}, err
	}
	var creator any
	if createdBy > 0 {
		creator = createdBy
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_tokens (user_id, purpose, token_hash, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		userID, purpose, HashAPITokenSecret(secret), creator, now, expires); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, err
	}
	return secret, expires, nil
}

func (store *userTokenStore) lookup(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, secret, purpose string, forUpdate bool) (int64, UserTokenPeek, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" || !validUserTokenPurpose(purpose) {
		return 0, UserTokenPeek{}, errNotFound
	}
	query := `
		SELECT t.id, t.user_id, t.expires_at, t.used_at, u.email, u.name
		FROM user_tokens t
		INNER JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = ? AND t.purpose = ?`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var id int64
	var peek UserTokenPeek
	var usedAt sql.NullTime
	err := q.QueryRowContext(ctx, query, HashAPITokenSecret(secret), purpose).Scan(
		&id, &peek.UserID, &peek.ExpiresAt, &usedAt, &peek.Email, &peek.Name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, UserTokenPeek{}, errNotFound
		}
		return 0, UserTokenPeek{}, err
	}
	if usedAt.Valid || !peek.ExpiresAt.After(time.Now().UTC()) {
		return 0, UserTokenPeek{}, errNotFound
	}
	peek.Purpose = purpose
	return id, peek, nil
}

func (store *userTokenStore) Peek(ctx context.Context, secret, purpose string) (UserTokenPeek, error) {
	_, peek, err := store.lookup(ctx, store.db, secret, purpose, false)
	return peek, err
}

func (store *userTokenStore) Consume(ctx context.Context, secret, purpose string) (UserTokenPeek, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return UserTokenPeek{}, err
	}
	defer func() { _ = tx.Rollback() }()
	id, peek, err := store.lookup(ctx, tx, secret, purpose, true)
	if err != nil {
		return UserTokenPeek{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_tokens SET used_at = ? WHERE id = ?`, time.Now().UTC(), id); err != nil {
		return UserTokenPeek{}, err
	}
	if err := tx.Commit(); err != nil {
		return UserTokenPeek{}, err
	}
	return peek, nil
}
