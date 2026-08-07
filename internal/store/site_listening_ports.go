package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type SitePortOption struct {
	ID          int64  `json:"id"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type SiteServerPorts struct {
	ServerID             int64            `json:"serverId"`
	Name                 string           `json:"name"`
	IP                   string           `json:"ip"`
	HTTPPorts            []SitePortOption `json:"httpPorts"`
	HTTPSPorts           []SitePortOption `json:"httpsPorts"`
	SelectedHTTPPortIDs  []int64          `json:"selectedHttpPortIds"`
	SelectedHTTPSPortIDs []int64          `json:"selectedHttpsPortIds"`
}

type SitePortsConfig struct {
	Servers []SiteServerPorts `json:"servers"`
}

type SiteEdgeServer struct {
	ID   int64
	Name string
	IP   string
}

type SiteListeningPortStore interface {
	BuildConfig(ctx context.Context, siteID int64, edges []SiteEdgeServer) (SitePortsConfig, error)
	ListPortsForServer(ctx context.Context, serverID int64) ([]ListeningPort, error)
	ReplaceForServer(ctx context.Context, siteID, serverID int64, portIDs []int64) error
	DeleteForServers(ctx context.Context, siteID int64, serverIDs []int64) error
}

type siteListeningPortStore struct {
	db *sql.DB
}

func NewSiteListeningPortStore(db *sql.DB) SiteListeningPortStore {
	return &siteListeningPortStore{db: db}
}

func (store *siteListeningPortStore) BuildConfig(ctx context.Context, siteID int64, edges []SiteEdgeServer) (SitePortsConfig, error) {
	selected, err := store.listSelectedBySite(ctx, siteID)
	if err != nil {
		return SitePortsConfig{}, err
	}
	selectedSet := make(map[int64]struct{}, len(selected))
	for _, id := range selected {
		selectedSet[id] = struct{}{}
	}

	out := SitePortsConfig{Servers: make([]SiteServerPorts, 0, len(edges))}
	for _, edge := range edges {
		ports, err := store.ListPortsForServer(ctx, edge.ID)
		if err != nil {
			return SitePortsConfig{}, err
		}
		entry := SiteServerPorts{
			ServerID:             edge.ID,
			Name:                 edge.Name,
			IP:                   edge.IP,
			HTTPPorts:            make([]SitePortOption, 0),
			HTTPSPorts:           make([]SitePortOption, 0),
			SelectedHTTPPortIDs:  make([]int64, 0),
			SelectedHTTPSPortIDs: make([]int64, 0),
		}
		for _, port := range ports {
			option := SitePortOption{
				ID:          port.ID,
				Port:        port.Port,
				Protocol:    port.Protocol,
				Description: port.Description,
				Status:      port.Status,
			}
			protocol := strings.ToUpper(strings.TrimSpace(port.Protocol))
			switch protocol {
			case "HTTPS":
				entry.HTTPSPorts = append(entry.HTTPSPorts, option)
				if _, ok := selectedSet[port.ID]; ok {
					entry.SelectedHTTPSPortIDs = append(entry.SelectedHTTPSPortIDs, port.ID)
				}
			default:
				entry.HTTPPorts = append(entry.HTTPPorts, option)
				if _, ok := selectedSet[port.ID]; ok {
					entry.SelectedHTTPPortIDs = append(entry.SelectedHTTPPortIDs, port.ID)
				}
			}
		}
		out.Servers = append(out.Servers, entry)
	}
	return out, nil
}

func (store *siteListeningPortStore) listSelectedBySite(ctx context.Context, siteID int64) ([]int64, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT listening_port_id
		FROM site_listening_ports
		WHERE site_id = ?
		ORDER BY listening_port_id ASC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (store *siteListeningPortStore) ListPortsForServer(ctx context.Context, serverID int64) ([]ListeningPort, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, server_id, port, protocol, description, status
		FROM listening_ports
		WHERE server_id = ?
		ORDER BY port ASC, id ASC`, serverID)
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
	return ports, rows.Err()
}

func (store *siteListeningPortStore) ReplaceForServer(ctx context.Context, siteID, serverID int64, portIDs []int64) error {
	uniqueIDs := uniqueInt64(portIDs)

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if len(uniqueIDs) > 0 {
		placeholders := make([]string, 0, len(uniqueIDs))
		args := make([]any, 0, len(uniqueIDs)+1)
		args = append(args, serverID)
		for _, id := range uniqueIDs {
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		query := fmt.Sprintf(`
			SELECT id
			FROM listening_ports
			WHERE server_id = ? AND id IN (%s)`, strings.Join(placeholders, ","))
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		found := make(map[int64]struct{}, len(uniqueIDs))
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			found[id] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(found) != len(uniqueIDs) {
			return fmt.Errorf("one or more listening ports do not belong to server %d", serverID)
		}
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE slp
		FROM site_listening_ports slp
		INNER JOIN listening_ports lp ON lp.id = slp.listening_port_id
		WHERE slp.site_id = ? AND lp.server_id = ?`, siteID, serverID); err != nil {
		return err
	}

	for _, id := range uniqueIDs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO site_listening_ports (site_id, listening_port_id)
			VALUES (?, ?)`, siteID, id); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (store *siteListeningPortStore) DeleteForServers(ctx context.Context, siteID int64, serverIDs []int64) error {
	ids := uniqueInt64(serverIDs)
	if len(ids) == 0 {
		return nil
	}
	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids)+1)
	args = append(args, siteID)
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	query := fmt.Sprintf(`
		DELETE slp
		FROM site_listening_ports slp
		INNER JOIN listening_ports lp ON lp.id = slp.listening_port_id
		WHERE slp.site_id = ? AND lp.server_id IN (%s)`, strings.Join(placeholders, ","))
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}
