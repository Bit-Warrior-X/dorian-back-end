package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/go-sql-driver/mysql"
)

const recoveryCodeCount = 10

// ErrMFAUnavailable means scripts/add_user_mfa.sql has not been applied yet.
var ErrMFAUnavailable = errors.New("two-factor authentication is not available: apply scripts/add_user_mfa.sql")

type MFAStatus struct {
	Enabled                bool `json:"enabled"`
	RecoveryCodesRemaining int  `json:"recoveryCodesRemaining"`
}

type MFAStore interface {
	Status(ctx context.Context, userID int64) (MFAStatus, error)
	EnabledUserIDs(ctx context.Context) (map[int64]bool, error)
	// Secret returns the active TOTP secret ("" when 2FA is off) and the last accepted step.
	Secret(ctx context.Context, userID int64) (string, int64, error)
	SetPendingSecret(ctx context.Context, userID int64, secret string) error
	PendingSecret(ctx context.Context, userID int64) (string, error)
	// Enable activates secret and returns freshly generated recovery codes (shown once).
	Enable(ctx context.Context, userID int64, secret string, step int64) ([]string, error)
	Disable(ctx context.Context, userID int64) error
	// AdvanceStep atomically records step as used; false means it was already used.
	AdvanceStep(ctx context.Context, userID int64, step int64) (bool, error)
	ConsumeRecoveryCode(ctx context.Context, userID int64, code string) (bool, error)
	RegenerateRecoveryCodes(ctx context.Context, userID int64) ([]string, error)
}

type mfaStore struct {
	db *sql.DB
}

func NewMFAStore(db *sql.DB) MFAStore {
	return &mfaStore{db: db}
}

func IsMFAUnavailable(err error) bool {
	return errors.Is(err, ErrMFAUnavailable)
}

func wrapMFAErr(err error) error {
	var mysqlErr *mysql.MySQLError
	// 1054 unknown column, 1146 unknown table.
	if errors.As(err, &mysqlErr) && (mysqlErr.Number == 1054 || mysqlErr.Number == 1146) {
		return ErrMFAUnavailable
	}
	return err
}

func (s *mfaStore) Status(ctx context.Context, userID int64) (MFAStatus, error) {
	var secret sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT totp_secret FROM users WHERE id = ?`, userID).Scan(&secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MFAStatus{}, errNotFound
		}
		return MFAStatus{}, wrapMFAErr(err)
	}
	status := MFAStatus{Enabled: secret.Valid && secret.String != ""}
	if !status.Enabled {
		return status, nil
	}
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID,
	).Scan(&status.RecoveryCodesRemaining)
	return status, wrapMFAErr(err)
}

func (s *mfaStore) EnabledUserIDs(ctx context.Context) (map[int64]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM users WHERE totp_secret IS NOT NULL AND totp_secret <> ''`)
	if err != nil {
		return nil, wrapMFAErr(err)
	}
	defer rows.Close()
	result := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result[id] = true
	}
	return result, rows.Err()
}

func (s *mfaStore) Secret(ctx context.Context, userID int64) (string, int64, error) {
	var secret sql.NullString
	var lastStep int64
	err := s.db.QueryRowContext(ctx,
		`SELECT totp_secret, totp_last_step FROM users WHERE id = ?`, userID,
	).Scan(&secret, &lastStep)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", 0, errNotFound
		}
		return "", 0, wrapMFAErr(err)
	}
	return secret.String, lastStep, nil
}

func (s *mfaStore) SetPendingSecret(ctx context.Context, userID int64, secret string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_pending_secret = ? WHERE id = ?`, secret, userID)
	return wrapMFAErr(err)
}

func (s *mfaStore) PendingSecret(ctx context.Context, userID int64) (string, error) {
	var secret sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT totp_pending_secret FROM users WHERE id = ?`, userID).Scan(&secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errNotFound
		}
		return "", wrapMFAErr(err)
	}
	return secret.String, nil
}

func (s *mfaStore) Enable(ctx context.Context, userID int64, secret string, step int64) ([]string, error) {
	codes, hashes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE users
		SET totp_secret = ?, totp_pending_secret = NULL, totp_enabled_at = NOW(), totp_last_step = ?
		WHERE id = ?`, secret, step, userID); err != nil {
		return nil, wrapMFAErr(err)
	}
	if err := replaceRecoveryCodes(ctx, tx, userID, hashes); err != nil {
		return nil, wrapMFAErr(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

func (s *mfaStore) Disable(ctx context.Context, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE users
		SET totp_secret = NULL, totp_pending_secret = NULL, totp_enabled_at = NULL, totp_last_step = 0
		WHERE id = ?`, userID); err != nil {
		return wrapMFAErr(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return wrapMFAErr(err)
	}
	return tx.Commit()
}

func (s *mfaStore) AdvanceStep(ctx context.Context, userID int64, step int64) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, userID, step)
	if err != nil {
		return false, wrapMFAErr(err)
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (s *mfaStore) ConsumeRecoveryCode(ctx context.Context, userID int64, code string) (bool, error) {
	normalized := normalizeRecoveryCode(code)
	if normalized == "" {
		return false, nil
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE user_recovery_codes SET used_at = NOW()
		WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
		userID, hashRecoveryCode(normalized))
	if err != nil {
		return false, wrapMFAErr(err)
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (s *mfaStore) RegenerateRecoveryCodes(ctx context.Context, userID int64) ([]string, error) {
	codes, hashes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := replaceRecoveryCodes(ctx, tx, userID, hashes); err != nil {
		return nil, wrapMFAErr(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

func replaceRecoveryCodes(ctx context.Context, tx *sql.Tx, userID int64, hashes []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, hash := range hashes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (?, ?)`, userID, hash); err != nil {
			return err
		}
	}
	return nil
}

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// generateRecoveryCodes returns display codes like "k3x9q-7mbd2" (50 bits each)
// and their SHA-256 hashes. High entropy makes a fast hash sufficient.
func generateRecoveryCodes(n int) ([]string, []string, error) {
	codes := make([]string, 0, n)
	hashes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 7)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, err
		}
		raw := strings.ToLower(recoveryEncoding.EncodeToString(buf))[:10]
		codes = append(codes, raw[:5]+"-"+raw[5:])
		hashes = append(hashes, hashRecoveryCode(raw))
	}
	return codes, hashes, nil
}

func normalizeRecoveryCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, "-", "")
	return strings.ReplaceAll(code, " ", "")
}

func hashRecoveryCode(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
