package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const APITokenPrefix = "dorian_pat_"

type APIToken struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"userId"`
	Name       string     `json:"name"`
	TokenPrefix string    `json:"tokenPrefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

type APITokenCreateInput struct {
	UserID    int64
	Name      string
	Scopes    []string
	ExpiresAt *time.Time
}

type APITokenCreateResult struct {
	Token  APIToken `json:"token"`
	Secret string   `json:"secret"`
}

type APITokenLookup struct {
	Token APIToken
	User  User
}

type APITokenStore interface {
	ListByUser(ctx context.Context, userID int64) ([]APIToken, error)
	Create(ctx context.Context, input APITokenCreateInput) (APITokenCreateResult, error)
	Revoke(ctx context.Context, userID, tokenID int64) error
	LookupActiveBySecret(ctx context.Context, secret string) (APITokenLookup, error)
	TouchLastUsed(ctx context.Context, tokenID int64) error
}

type apiTokenStore struct {
	db *sql.DB
}

func NewAPITokenStore(db *sql.DB) APITokenStore {
	return &apiTokenStore{db: db}
}

func HashAPITokenSecret(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return hex.EncodeToString(sum[:])
}

func (store *apiTokenStore) ListByUser(ctx context.Context, userID int64) ([]APIToken, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, user_id, name, token_prefix, scopes, expires_at, last_used_at, created_at, revoked_at
		FROM api_tokens
		WHERE user_id = ? AND revoked_at IS NULL
		ORDER BY created_at DESC, id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]APIToken, 0)
	for rows.Next() {
		item, scanErr := scanAPIToken(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (store *apiTokenStore) Create(ctx context.Context, input APITokenCreateInput) (APITokenCreateResult, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return APITokenCreateResult{}, errors.New("token name is required")
	}
	if input.UserID <= 0 {
		return APITokenCreateResult{}, errors.New("user id is required")
	}
	scopes := normalizeScopes(input.Scopes)
	secret, prefix, err := generateAPITokenSecret()
	if err != nil {
		return APITokenCreateResult{}, err
	}
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return APITokenCreateResult{}, err
	}

	var expires any
	if input.ExpiresAt != nil {
		expires = *input.ExpiresAt
	}

	result, err := store.db.ExecContext(ctx, `
		INSERT INTO api_tokens (user_id, name, token_prefix, token_hash, scopes, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		input.UserID, name, prefix, HashAPITokenSecret(secret), string(scopesJSON), expires)
	if err != nil {
		return APITokenCreateResult{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return APITokenCreateResult{}, err
	}

	item := APIToken{
		ID:          id,
		UserID:      input.UserID,
		Name:        name,
		TokenPrefix: prefix,
		Scopes:      scopes,
		ExpiresAt:   input.ExpiresAt,
		CreatedAt:   time.Now().UTC(),
	}
	return APITokenCreateResult{Token: item, Secret: secret}, nil
}

func (store *apiTokenStore) Revoke(ctx context.Context, userID, tokenID int64) error {
	result, err := store.db.ExecContext(ctx, `
		UPDATE api_tokens
		SET revoked_at = CURRENT_TIMESTAMP(6)
		WHERE id = ? AND user_id = ? AND revoked_at IS NULL`, tokenID, userID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errNotFound
	}
	return nil
}

func (store *apiTokenStore) LookupActiveBySecret(ctx context.Context, secret string) (APITokenLookup, error) {
	secret = strings.TrimSpace(secret)
	if !strings.HasPrefix(secret, APITokenPrefix) {
		return APITokenLookup{}, errNotFound
	}
	hash := HashAPITokenSecret(secret)

	row := store.db.QueryRowContext(ctx, `
		SELECT
			t.id, t.user_id, t.name, t.token_prefix, t.scopes, t.expires_at, t.last_used_at, t.created_at, t.revoked_at,
			u.id, u.name, u.email, u.password, u.role, u.status
		FROM api_tokens t
		INNER JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = ? AND t.revoked_at IS NULL
		LIMIT 1`, hash)

	var token APIToken
	var scopesRaw sql.NullString
	var expiresAt, lastUsedAt, revokedAt sql.NullTime
	var user User
	if err := row.Scan(
		&token.ID, &token.UserID, &token.Name, &token.TokenPrefix, &scopesRaw, &expiresAt, &lastUsedAt, &token.CreatedAt, &revokedAt,
		&user.ID, &user.Name, &user.Email, &user.Password, &user.Role, &user.Status,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return APITokenLookup{}, errNotFound
		}
		return APITokenLookup{}, err
	}
	token.Scopes = decodeScopes(scopesRaw.String)
	if expiresAt.Valid {
		value := expiresAt.Time
		token.ExpiresAt = &value
		if value.Before(time.Now().UTC()) {
			return APITokenLookup{}, errNotFound
		}
	}
	if lastUsedAt.Valid {
		value := lastUsedAt.Time
		token.LastUsedAt = &value
	}
	if revokedAt.Valid {
		return APITokenLookup{}, errNotFound
	}
	if !strings.EqualFold(user.Status, "Active") {
		return APITokenLookup{}, errNotFound
	}
	return APITokenLookup{Token: token, User: user}, nil
}

func (store *apiTokenStore) TouchLastUsed(ctx context.Context, tokenID int64) error {
	_, err := store.db.ExecContext(ctx, `
		UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP(6) WHERE id = ?`, tokenID)
	return err
}

type apiTokenScanner interface {
	Scan(dest ...any) error
}

func scanAPIToken(row apiTokenScanner) (APIToken, error) {
	var item APIToken
	var scopesRaw sql.NullString
	var expiresAt, lastUsedAt, revokedAt sql.NullTime
	if err := row.Scan(
		&item.ID, &item.UserID, &item.Name, &item.TokenPrefix, &scopesRaw,
		&expiresAt, &lastUsedAt, &item.CreatedAt, &revokedAt,
	); err != nil {
		return APIToken{}, err
	}
	item.Scopes = decodeScopes(scopesRaw.String)
	if expiresAt.Valid {
		value := expiresAt.Time
		item.ExpiresAt = &value
	}
	if lastUsedAt.Valid {
		value := lastUsedAt.Time
		item.LastUsedAt = &value
	}
	if revokedAt.Valid {
		value := revokedAt.Time
		item.RevokedAt = &value
	}
	return item, nil
}

func normalizeScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{"*"}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		trimmed := strings.TrimSpace(scope)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}

func decodeScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{"*"}
	}
	var scopes []string
	if err := json.Unmarshal([]byte(raw), &scopes); err != nil {
		return []string{"*"}
	}
	return normalizeScopes(scopes)
}

func generateAPITokenSecret() (secret, prefix string, err error) {
	buf := make([]byte, 24)
	if _, err = rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate token: %w", err)
	}
	body := hex.EncodeToString(buf)
	secret = APITokenPrefix + body
	prefix = APITokenPrefix + body[:8]
	return secret, prefix, nil
}
