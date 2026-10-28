package store

import (
	"context"
	"database/sql"
	"strings"
)

type ListeningPort struct {
	ID          int64  `json:"id"`
	ServerID    int64  `json:"serverId"`
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
	ListByServer(ctx context.Context, serverID int64) ([]ListeningPort, error)
	Create(ctx context.Context, serverID int64, port ListeningPortInput) (ListeningPort, error)
	Update(ctx context.Context, serverID, portID int64, port ListeningPortInput) (ListeningPort, error)
	Delete(ctx context.Context, serverID, portID int64) error
	DeleteBatch(ctx context.Context, serverID int64, portIDs []int64) error
	ReplaceByServer(ctx context.Context, serverID int64, ports []ListeningPortInput) ([]ListeningPort, error)
}

type listeningPortStore struct {
	db *sql.DB
}

func NewListeningPortStore(db *sql.DB) ListeningPortStore {
	return &listeningPortStore{db: db}
}

func (store *listeningPortStore) ListByServer(ctx context.Context, serverID int64) ([]ListeningPort, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, server_id, port, protocol, description, status
		FROM listening_ports
		WHERE server_id = ?
		ORDER BY port ASC, id DESC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ports := make([]ListeningPort, 0)
	for rows.Next() {
		var port ListeningPort
		var protocol sql.NullString
		var status sql.NullString
		if err := rows.Scan(&port.ID, &port.ServerID, &port.Port, &protocol, &port.Description, &status); err != nil {
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

func (store *listeningPortStore) Create(ctx context.Context, serverID int64, port ListeningPortInput) (ListeningPort, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO listening_ports (server_id, port, protocol, description, status)
		VALUES (?, ?, ?, ?, ?)`,
		serverID,
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
		ServerID:    serverID,
		Port:        port.Port,
		Protocol:    port.Protocol,
		Description: port.Description,
		Status:      port.Status,
	}, nil
}

func (store *listeningPortStore) Update(ctx context.Context, serverID, portID int64, port ListeningPortInput) (ListeningPort, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE listening_ports
		SET port = ?, protocol = ?, description = ?, status = ?
		WHERE id = ? AND server_id = ?`,
		port.Port,
		nullableServerString(port.Protocol),
		port.Description,
		nullableServerString(port.Status),
		portID,
		serverID,
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
		// MySQL reports 0 when values are unchanged. Confirm the row still exists
		// so report_edge_configure does not insert a duplicate every minute.
		var exists int
		if err := store.db.QueryRowContext(ctx, `
			SELECT 1 FROM listening_ports WHERE id = ? AND server_id = ?`, portID, serverID).Scan(&exists); err != nil {
			if err == sql.ErrNoRows {
				return ListeningPort{}, errNotFound
			}
			return ListeningPort{}, err
		}
	}

	return ListeningPort{
		ID:          portID,
		ServerID:    serverID,
		Port:        port.Port,
		Protocol:    port.Protocol,
		Description: port.Description,
		Status:      port.Status,
	}, nil
}

func (store *listeningPortStore) Delete(ctx context.Context, serverID, portID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM listening_ports WHERE id = ? AND server_id = ?`,
		portID,
		serverID,
	)
	return err
}

func (store *listeningPortStore) DeleteBatch(ctx context.Context, serverID int64, portIDs []int64) error {
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
	args = append(args, serverID)

	query := "DELETE FROM listening_ports WHERE id IN (" + strings.Join(placeholders, ",") + ") AND server_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}

func normalizeListeningProtocol(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "HTTPS") {
		return "HTTPS"
	}
	if strings.EqualFold(strings.TrimSpace(value), "HTTP") {
		return "HTTP"
	}
	return strings.TrimSpace(value)
}

func (store *listeningPortStore) ReplaceByServer(ctx context.Context, serverID int64, ports []ListeningPortInput) ([]ListeningPort, error) {
	if serverID == 0 {
		return nil, errNotFound
	}
	existing, err := store.ListByServer(ctx, serverID)
	if err != nil {
		return nil, err
	}

	type key struct {
		port     int
		protocol string
	}
	// One row per port/protocol. Prefer an id still selected by a site, else the lowest id.
	referenced := map[int64]struct{}{}
	if rows, err := store.db.QueryContext(ctx, `
		SELECT DISTINCT slp.listening_port_id
		FROM site_listening_ports slp
		INNER JOIN listening_ports lp ON lp.id = slp.listening_port_id
		WHERE lp.server_id = ?`, serverID); err == nil {
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err == nil {
				referenced[id] = struct{}{}
			}
		}
		rows.Close()
	}
	prefer := func(candidate, current ListeningPort) bool {
		_, candidateRef := referenced[candidate.ID]
		_, currentRef := referenced[current.ID]
		if candidateRef != currentRef {
			return candidateRef
		}
		return candidate.ID < current.ID
	}
	existingByKey := make(map[key]ListeningPort, len(existing))
	var duplicateIDs []int64
	for _, port := range existing {
		k := key{port: port.Port, protocol: strings.ToUpper(normalizeListeningProtocol(port.Protocol))}
		if current, ok := existingByKey[k]; ok {
			if prefer(port, current) {
				duplicateIDs = append(duplicateIDs, current.ID)
				existingByKey[k] = port
			} else {
				duplicateIDs = append(duplicateIDs, port.ID)
			}
			continue
		}
		existingByKey[k] = port
	}

	desiredKeys := make(map[key]struct{}, len(ports))
	out := make([]ListeningPort, 0, len(ports))
	for _, input := range ports {
		if input.Port <= 0 || input.Port > 65535 {
			continue
		}
		protocol := normalizeListeningProtocol(input.Protocol)
		if protocol == "" {
			protocol = "HTTP"
		}
		status := strings.TrimSpace(input.Status)
		if status == "" {
			status = "ENABLE"
		}
		k := key{port: input.Port, protocol: strings.ToUpper(protocol)}
		if _, seen := desiredKeys[k]; seen {
			continue
		}
		desiredKeys[k] = struct{}{}
		normalized := ListeningPortInput{
			Port:        input.Port,
			Protocol:    protocol,
			Description: strings.TrimSpace(input.Description),
			Status:      status,
		}
		if current, ok := existingByKey[k]; ok {
			updated, err := store.Update(ctx, serverID, current.ID, normalized)
			if err == nil {
				out = append(out, updated)
				continue
			}
			// Row may have been deleted by a concurrent sync; fall through to create.
			if !IsNotFound(err) {
				return nil, err
			}
		}
		created, err := store.Create(ctx, serverID, normalized)
		if err != nil {
			return nil, err
		}
		out = append(out, created)
	}

	var toDelete []int64
	toDelete = append(toDelete, duplicateIDs...)
	for k, port := range existingByKey {
		if _, keep := desiredKeys[k]; !keep {
			toDelete = append(toDelete, port.ID)
		}
	}
	if err := store.DeleteBatch(ctx, serverID, toDelete); err != nil {
		return nil, err
	}
	return out, nil
}
