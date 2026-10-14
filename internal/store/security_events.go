package store

import (
	"context"
	"database/sql"
)

type SecurityEvent struct {
	ID          int64  `json:"id"`
	ServerID    *int64 `json:"serverId,omitempty"`
	ServerName  string `json:"serverName,omitempty"`
	Title       string `json:"title"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type SecurityEventStore interface {
	ListRecent(ctx context.Context, limit int, scope TrafficScope) ([]SecurityEvent, error)
	// Create records an event reported by an edge; serverID 0 stores no edge.
	Create(ctx context.Context, serverID int64, title, description string) error
}

type securityEventStore struct {
	db *sql.DB
}

func NewSecurityEventStore(db *sql.DB) SecurityEventStore {
	return &securityEventStore{db: db}
}

func (store *securityEventStore) ListRecent(ctx context.Context, limit int, scope TrafficScope) ([]SecurityEvent, error) {
	if limit <= 0 {
		limit = 5
	}
	query, args := appendServerScope(`
		SELECT e.id, e.server_id, s.name, e.title, e.description, e.created_at, e.updated_at
		FROM security_events e
		LEFT JOIN servers s ON s.id = e.server_id
		WHERE 1 = 1`, nil, scope)
	query += " ORDER BY e.created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		var item SecurityEvent
		var serverID sql.NullInt64
		var serverName sql.NullString
		var createdAt sql.NullTime
		var updatedAt sql.NullTime
		if err := rows.Scan(&item.ID, &serverID, &serverName, &item.Title, &item.Description, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		if serverID.Valid {
			value := serverID.Int64
			item.ServerID = &value
		}
		item.ServerName = serverName.String
		item.CreatedAt = formatTimestamp(createdAt)
		item.UpdatedAt = formatTimestamp(updatedAt)
		events = append(events, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (store *securityEventStore) Create(ctx context.Context, serverID int64, title, description string) error {
	var server any
	if serverID > 0 {
		server = serverID
	}
	_, err := store.db.ExecContext(ctx, `
		INSERT INTO security_events (server_id, title, description, created_at, updated_at)
		VALUES (?, ?, ?, NOW(), NOW())`,
		server,
		title,
		description,
	)
	return err
}
