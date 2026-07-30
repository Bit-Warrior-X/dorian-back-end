package store

import (
	"context"
	"database/sql"
	"strings"
)

type ListeningPort struct {
	ID          int64  `json:"id"`
	SiteID    int64  `json:"siteId"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type ListeningPortInput struct {
	Port        int
	Protocol    string
	Description string
	Status      string
}

type ListeningPortStore interface {
	ListBySite(ctx context.Context, siteID int64) ([]ListeningPort, error)
	Create(ctx context.Context, siteID int64, port ListeningPortInput) (ListeningPort, error)
	Update(ctx context.Context, siteID, portID int64, port ListeningPortInput) (ListeningPort, error)
	Delete(ctx context.Context, siteID, portID int64) error
	DeleteBatch(ctx context.Context, siteID int64, portIDs []int64) error
}

type listeningPortStore struct {
	db *sql.DB
}

func NewListeningPortStore(db *sql.DB) ListeningPortStore {
	return &listeningPortStore{db: db}
}

func (store *listeningPortStore) ListBySite(ctx context.Context, siteID int64) ([]ListeningPort, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, site_id, port, protocol, description, status
		FROM listening_ports
		WHERE site_id = ?
		ORDER BY port ASC, id DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []ListeningPort
	for rows.Next() {
		var port ListeningPort
		var protocol sql.NullString
		var status sql.NullString
		if err := rows.Scan(&port.ID, &port.SiteID, &port.Port, &protocol, &port.Description, &status); err != nil {
			return nil, err
		}
		port.Protocol = nullStringValue(protocol)
		port.Status = nullStringValue(status)
		ports = append(ports, port)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ports, nil
}

func (store *listeningPortStore) Create(ctx context.Context, siteID int64, port ListeningPortInput) (ListeningPort, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO listening_ports (site_id, port, protocol, description, status)
		VALUES (?, ?, ?, ?, ?)`,
		siteID,
		port.Port,
		nullableServerString(port.Protocol),
		port.Description,
		nullableServerString(port.Status),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return ListeningPort{}, errNotFound
		}
		return ListeningPort{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return ListeningPort{}, err
	}

	return ListeningPort{
		ID:          id,
		SiteID:    siteID,
		Port:        port.Port,
		Protocol:    port.Protocol,
		Description: port.Description,
		Status:      port.Status,
	}, nil
}

func (store *listeningPortStore) Update(ctx context.Context, siteID, portID int64, port ListeningPortInput) (ListeningPort, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE listening_ports
		SET port = ?, protocol = ?, description = ?, status = ?
		WHERE id = ? AND site_id = ?`,
		port.Port,
		nullableServerString(port.Protocol),
		port.Description,
		nullableServerString(port.Status),
		portID,
		siteID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return ListeningPort{}, errNotFound
		}
		return ListeningPort{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return ListeningPort{}, err
	}
	if affected == 0 {
		return ListeningPort{}, errNotFound
	}

	return ListeningPort{
		ID:          portID,
		SiteID:    siteID,
		Port:        port.Port,
		Protocol:    port.Protocol,
		Description: port.Description,
		Status:      port.Status,
	}, nil
}

func (store *listeningPortStore) Delete(ctx context.Context, siteID, portID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM listening_ports WHERE id = ? AND site_id = ?`,
		portID,
		siteID,
	)
	return err
}

func (store *listeningPortStore) DeleteBatch(ctx context.Context, siteID int64, portIDs []int64) error {
	ids := uniqueInt64(portIDs)
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

	query := "DELETE FROM listening_ports WHERE id IN (" + strings.Join(placeholders, ",") + ") AND site_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}
