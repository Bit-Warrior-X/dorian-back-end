package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type L4BlacklistEntry struct {
	ID        int64  `json:"id"`
	ServerID  int64  `json:"serverId"`
	IPAddress string `json:"ipAddress"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type L4BlacklistInput struct {
	IPAddress string
	Reason    string
}

type L4BlacklistStore interface {
	ListByServer(ctx context.Context, serverID int64) ([]L4BlacklistEntry, error)
	Create(ctx context.Context, serverID int64, input L4BlacklistInput) (L4BlacklistEntry, error)
	Delete(ctx context.Context, serverID, entryID int64) error
	DeleteAll(ctx context.Context, serverID int64) error
	ReplaceByServer(ctx context.Context, serverID int64, entries []L4BlacklistInput) error
}

type l4BlacklistStore struct {
	db *sql.DB
}

func NewL4BlacklistStore(db *sql.DB) L4BlacklistStore {
	return &l4BlacklistStore{db: db}
}

func (store *l4BlacklistStore) ListByServer(ctx context.Context, serverID int64) ([]L4BlacklistEntry, error) {
	if serverID == 0 {
		return nil, nil
	}

	rows, err := store.db.QueryContext(ctx, `
		SELECT id, server_id, source_ip, reason, created_at, updated_at
		FROM l4_blacklist
		WHERE server_id = ?
		ORDER BY id DESC`,
		serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []L4BlacklistEntry
	for rows.Next() {
		var entry L4BlacklistEntry
		var reason sql.NullString
		var createdAt sql.NullTime
		var updatedAt sql.NullTime
		if err := rows.Scan(
			&entry.ID,
			&entry.ServerID,
			&entry.IPAddress,
			&reason,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}

		entry.Reason = strings.TrimSpace(nullStringValue(reason))
		entry.CreatedAt = formatTimestamp(createdAt)
		entry.UpdatedAt = formatTimestamp(updatedAt)

		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (store *l4BlacklistStore) Create(ctx context.Context, serverID int64, input L4BlacklistInput) (L4BlacklistEntry, error) {
	if serverID == 0 {
		return L4BlacklistEntry{}, errNotFound
	}

	result, err := store.db.ExecContext(ctx, `
		INSERT INTO l4_blacklist (server_id, source_ip, reason)
		VALUES (?, ?, ?)`,
		serverID,
		strings.TrimSpace(input.IPAddress),
		nullableServerString(input.Reason),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return L4BlacklistEntry{}, errNotFound
		}
		return L4BlacklistEntry{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return L4BlacklistEntry{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339)

	return L4BlacklistEntry{
		ID:        id,
		ServerID:  serverID,
		IPAddress: strings.TrimSpace(input.IPAddress),
		Reason:    strings.TrimSpace(input.Reason),
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (store *l4BlacklistStore) Delete(ctx context.Context, serverID, entryID int64) error {
	if serverID == 0 || entryID == 0 {
		return nil
	}
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM l4_blacklist
		WHERE id = ? AND server_id = ?`,
		entryID,
		serverID,
	)
	return err
}

func (store *l4BlacklistStore) DeleteAll(ctx context.Context, serverID int64) error {
	if serverID == 0 {
		return nil
	}
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM l4_blacklist
		WHERE server_id = ?`,
		serverID,
	)
	return err
}

func (store *l4BlacklistStore) ReplaceByServer(ctx context.Context, serverID int64, entries []L4BlacklistInput) error {
	if serverID == 0 {
		return errNotFound
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM l4_blacklist WHERE server_id = ?`, serverID); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		ip := strings.TrimSpace(entry.IPAddress)
		if ip == "" {
			continue
		}
		key := strings.ToLower(ip)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO l4_blacklist (server_id, source_ip, reason)
			VALUES (?, ?, ?)`,
			serverID,
			ip,
			nullableServerString(entry.Reason),
		); err != nil {
			if isForeignKeyViolation(err) {
				return errNotFound
			}
			return err
		}
	}
	return tx.Commit()
}

