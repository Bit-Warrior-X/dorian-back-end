package store

import (
	"context"
	"database/sql"
	"time"
)

type L4LiveAttackStore interface {
	CountBetween(ctx context.Context, start, end time.Time) (int64, error)
	CountBetweenForServers(ctx context.Context, start, end time.Time, serverIDs []int64) (int64, error)
	Create(ctx context.Context, serverID int64, sourceIP, attackType string) error
}

type l4LiveAttackStore struct {
	db *sql.DB
}

func NewL4LiveAttackStore(db *sql.DB) L4LiveAttackStore {
	return &l4LiveAttackStore{db: db}
}

func (store *l4LiveAttackStore) CountBetweenForServers(ctx context.Context, start, end time.Time, serverIDs []int64) (int64, error) {
	query, args := appendIDAllowList(`
		SELECT COUNT(*)
		FROM l4_live_attack
		WHERE created_at >= ? AND created_at < ?`, []any{start, end}, "server_id", serverIDs)
	var total int64
	if err := store.db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *l4LiveAttackStore) CountBetween(ctx context.Context, start, end time.Time) (int64, error) {
	var total int64
	row := store.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM l4_live_attack
		WHERE created_at >= ? AND created_at < ?`,
		start,
		end,
	)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *l4LiveAttackStore) Create(ctx context.Context, serverID int64, sourceIP, attackType string) error {
	_, err := store.db.ExecContext(ctx, `
		INSERT INTO l4_live_attack (server_id, source_ip, attack_type, created_at)
		VALUES (?, ?, ?, NOW())`,
		serverID,
		sourceIP,
		attackType,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return errNotFound
		}
		return err
	}
	return nil
}
