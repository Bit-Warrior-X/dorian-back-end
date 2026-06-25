package store

import (
	"context"
	"database/sql"
	"net"
	"strconv"
	"strings"
)

type UpstreamServer struct {
	ID          int64  `json:"id"`
	ServerID    int64  `json:"serverId"`
	Address     string `json:"address"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type UpstreamServerInput struct {
	Address     string
	Description string
	Status      string
}

type UpstreamServerStore interface {
	ListByServer(ctx context.Context, serverID int64) ([]UpstreamServer, error)
	Create(ctx context.Context, serverID int64, server UpstreamServerInput) (UpstreamServer, error)
	Update(ctx context.Context, serverID, upstreamID int64, server UpstreamServerInput) (UpstreamServer, error)
	Delete(ctx context.Context, serverID, upstreamID int64) error
	DeleteBatch(ctx context.Context, serverID int64, upstreamIDs []int64) error
}

type upstreamServerStore struct {
	db *sql.DB
}

func NewUpstreamServerStore(db *sql.DB) UpstreamServerStore {
	return &upstreamServerStore{db: db}
}

// NormalizeUpstreamAddress canonicalizes an upstream ip:port for duplicate checks.
func NormalizeUpstreamAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return strings.ToLower(address)
	}

	if portNum, err := strconv.Atoi(port); err == nil {
		return strings.ToLower(host) + ":" + strconv.Itoa(portNum)
	}
	return strings.ToLower(host) + ":" + strings.ToLower(port)
}

func UpstreamAddressExists(list []UpstreamServer, address string, excludeID int64) bool {
	normalized := NormalizeUpstreamAddress(address)
	if normalized == "" {
		return false
	}
	for _, existing := range list {
		if existing.ID == excludeID {
			continue
		}
		if NormalizeUpstreamAddress(existing.Address) == normalized {
			return true
		}
	}
	return false
}

func (store *upstreamServerStore) ListByServer(ctx context.Context, serverID int64) ([]UpstreamServer, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, server_id, ip_port, description, status
		FROM upstream_servers
		WHERE server_id = ?
		ORDER BY id DESC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []UpstreamServer
	for rows.Next() {
		var server UpstreamServer
		var status sql.NullString
		if err := rows.Scan(&server.ID, &server.ServerID, &server.Address, &server.Description, &status); err != nil {
			return nil, err
		}
		server.Status = nullStringValue(status)
		servers = append(servers, server)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return servers, nil
}

func (store *upstreamServerStore) Create(ctx context.Context, serverID int64, server UpstreamServerInput) (UpstreamServer, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO upstream_servers (server_id, ip_port, description, status)
		VALUES (?, ?, ?, ?)`,
		serverID,
		server.Address,
		server.Description,
		nullableServerString(server.Status),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return UpstreamServer{}, errNotFound
		}
		return UpstreamServer{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return UpstreamServer{}, err
	}

	return UpstreamServer{
		ID:          id,
		ServerID:    serverID,
		Address:     server.Address,
		Description: server.Description,
		Status:      server.Status,
	}, nil
}

func (store *upstreamServerStore) Update(ctx context.Context, serverID, upstreamID int64, server UpstreamServerInput) (UpstreamServer, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE upstream_servers
		SET ip_port = ?, description = ?, status = ?
		WHERE id = ? AND server_id = ?`,
		server.Address,
		server.Description,
		nullableServerString(server.Status),
		upstreamID,
		serverID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return UpstreamServer{}, errNotFound
		}
		return UpstreamServer{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return UpstreamServer{}, err
	}
	if affected == 0 {
		return UpstreamServer{}, errNotFound
	}

	return UpstreamServer{
		ID:          upstreamID,
		ServerID:    serverID,
		Address:     server.Address,
		Description: server.Description,
		Status:      server.Status,
	}, nil
}

func (store *upstreamServerStore) Delete(ctx context.Context, serverID, upstreamID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM upstream_servers WHERE id = ? AND server_id = ?`,
		upstreamID,
		serverID,
	)
	return err
}

func (store *upstreamServerStore) DeleteBatch(ctx context.Context, serverID int64, upstreamIDs []int64) error {
	ids := uniqueInt64(upstreamIDs)
	if len(ids) == 0 {
		return nil
	}

	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids)+1)
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	args = append(args, serverID)

	query := "DELETE FROM upstream_servers WHERE id IN (" + strings.Join(placeholders, ",") + ") AND server_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}
