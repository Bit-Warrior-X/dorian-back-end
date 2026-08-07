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
	SiteID      int64  `json:"siteId"`
	Address     string `json:"address"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type UpstreamServerInput struct {
	Address     string
	Protocol    string
	Description string
	Status      string
}

type UpstreamServerStore interface {
	ListBySite(ctx context.Context, siteID int64) ([]UpstreamServer, error)
	Create(ctx context.Context, siteID int64, server UpstreamServerInput) (UpstreamServer, error)
	Update(ctx context.Context, siteID, upstreamID int64, server UpstreamServerInput) (UpstreamServer, error)
	Delete(ctx context.Context, siteID, upstreamID int64) error
	DeleteBatch(ctx context.Context, siteID int64, upstreamIDs []int64) error
}

type upstreamServerStore struct {
	db *sql.DB
}

func NewUpstreamServerStore(db *sql.DB) UpstreamServerStore {
	return &upstreamServerStore{db: db}
}

func NormalizeUpstreamProtocol(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "HTTPS") {
		return "HTTPS"
	}
	return "HTTP"
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

func (store *upstreamServerStore) ListBySite(ctx context.Context, siteID int64) ([]UpstreamServer, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, site_id, ip_port, protocol, description, status
		FROM upstream_servers
		WHERE site_id = ?
		ORDER BY id DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []UpstreamServer
	for rows.Next() {
		var server UpstreamServer
		var protocol sql.NullString
		var status sql.NullString
		if err := rows.Scan(&server.ID, &server.SiteID, &server.Address, &protocol, &server.Description, &status); err != nil {
			return nil, err
		}
		server.Protocol = NormalizeUpstreamProtocol(nullStringValue(protocol))
		server.Status = nullStringValue(status)
		servers = append(servers, server)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return servers, nil
}

func (store *upstreamServerStore) Create(ctx context.Context, siteID int64, server UpstreamServerInput) (UpstreamServer, error) {
	protocol := NormalizeUpstreamProtocol(server.Protocol)
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO upstream_servers (site_id, ip_port, protocol, description, status)
		VALUES (?, ?, ?, ?, ?)`,
		siteID,
		server.Address,
		protocol,
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
		SiteID:      siteID,
		Address:     server.Address,
		Protocol:    protocol,
		Description: server.Description,
		Status:      server.Status,
	}, nil
}

func (store *upstreamServerStore) Update(ctx context.Context, siteID, upstreamID int64, server UpstreamServerInput) (UpstreamServer, error) {
	protocol := NormalizeUpstreamProtocol(server.Protocol)
	result, err := store.db.ExecContext(ctx, `
		UPDATE upstream_servers
		SET ip_port = ?, protocol = ?, description = ?, status = ?
		WHERE id = ? AND site_id = ?`,
		server.Address,
		protocol,
		server.Description,
		nullableServerString(server.Status),
		upstreamID,
		siteID,
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
		SiteID:      siteID,
		Address:     server.Address,
		Protocol:    protocol,
		Description: server.Description,
		Status:      server.Status,
	}, nil
}

func (store *upstreamServerStore) Delete(ctx context.Context, siteID, upstreamID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM upstream_servers WHERE id = ? AND site_id = ?`,
		upstreamID,
		siteID,
	)
	return err
}

func (store *upstreamServerStore) DeleteBatch(ctx context.Context, siteID int64, upstreamIDs []int64) error {
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
	args = append(args, siteID)

	query := "DELETE FROM upstream_servers WHERE id IN (" + strings.Join(placeholders, ",") + ") AND site_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}
