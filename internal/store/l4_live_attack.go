package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type L4LiveAttackStore interface {
	CountBetween(ctx context.Context, start, end time.Time) (int64, error)
	CountBetweenForServers(ctx context.Context, start, end time.Time, serverIDs []int64) (int64, error)
	// Create records a live L4 block. occurredAt is the time the event happened.
	Create(ctx context.Context, serverID int64, sourceIP, attackType string, occurredAt time.Time, reqID string) error
	// ListBlocks returns the newest live blocks for an edge, optionally one attack id.
	ListBlocks(ctx context.Context, serverID int64, reqID string, since time.Time, limit int) ([]L4LiveBlock, error)
}

type L4LiveBlock struct {
	IP         string `json:"ip"`
	AttackType string `json:"attackType"`
	CreatedAt  string `json:"createdAt"`
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

func (store *l4LiveAttackStore) Create(ctx context.Context, serverID int64, sourceIP, attackType string, occurredAt time.Time, reqID string) error {
	if occurredAt.IsZero() {
		occurredAt = time.Now()
	}
	_, err := store.db.ExecContext(ctx, `
		INSERT INTO l4_live_attack (server_id, source_ip, attack_type, req_id, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		serverID,
		sourceIP,
		attackType,
		reqID,
		occurredAt,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return errNotFound
		}
		return err
	}
	return nil
}

func (store *l4LiveAttackStore) ListBlocks(ctx context.Context, serverID int64, reqID string, since time.Time, limit int) ([]L4LiveBlock, error) {
	if serverID == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 80
	}
	query := `
		SELECT source_ip, attack_type, created_at
		FROM l4_live_attack
		WHERE server_id = ?`
	args := []any{serverID}
	if stringsTrim := strings.TrimSpace(reqID); stringsTrim != "" {
		query += ` AND req_id = ?`
		args = append(args, stringsTrim)
	}
	if !since.IsZero() {
		query += ` AND created_at >= ?`
		args = append(args, since)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var blocks []L4LiveBlock
	for rows.Next() {
		var item L4LiveBlock
		var created sql.NullTime
		if err := rows.Scan(&item.IP, &item.AttackType, &created); err != nil {
			return nil, err
		}
		item.CreatedAt = formatTimestamp(created)
		blocks = append(blocks, item)
	}
	return blocks, rows.Err()
}
