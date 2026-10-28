package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

type SiteOriginRouteRule struct {
	ID          int64   `json:"id,omitempty"`
	Ports       []int   `json:"ports"`
	UpstreamIDs []int64 `json:"upstreamIds"`
}

type SiteOriginRoutes struct {
	HTTP  []SiteOriginRouteRule `json:"http"`
	HTTPS []SiteOriginRouteRule `json:"https"`
}

type SiteOriginRouteStore interface {
	EnsureSchema(ctx context.Context) error
	GetBySite(ctx context.Context, siteID int64) (SiteOriginRoutes, error)
	ReplaceForSite(ctx context.Context, siteID int64, routes SiteOriginRoutes) (SiteOriginRoutes, error)
}

type siteOriginRouteStore struct {
	db *sql.DB
}

func NewSiteOriginRouteStore(db *sql.DB) SiteOriginRouteStore {
	return &siteOriginRouteStore{db: db}
}

func NormalizeOriginRouteScheme(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "HTTPS") {
		return "HTTPS"
	}
	return "HTTP"
}

func (store *siteOriginRouteStore) EnsureSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS site_origin_routes (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			site_id bigint(20) NOT NULL,
			scheme enum('HTTP','HTTPS') NOT NULL,
			description varchar(255) NOT NULL DEFAULT '',
			created_at timestamp NULL DEFAULT current_timestamp(),
			updated_at timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
			PRIMARY KEY (id),
			KEY idx_site_origin_routes_site (site_id),
			KEY idx_site_origin_routes_site_scheme (site_id, scheme),
			CONSTRAINT site_origin_routes_site_fk FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE ON UPDATE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS site_origin_route_ports (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			route_id bigint(20) NOT NULL,
			site_id bigint(20) NOT NULL,
			scheme enum('HTTP','HTTPS') NOT NULL,
			port int(11) NOT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY uk_site_origin_route_ports_site_scheme_port (site_id, scheme, port),
			UNIQUE KEY uk_site_origin_route_ports_route_port (route_id, port),
			KEY idx_site_origin_route_ports_route (route_id),
			CONSTRAINT site_origin_route_ports_route_fk FOREIGN KEY (route_id) REFERENCES site_origin_routes (id) ON DELETE CASCADE ON UPDATE CASCADE,
			CONSTRAINT site_origin_route_ports_site_fk FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE ON UPDATE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS site_origin_route_upstreams (
			route_id bigint(20) NOT NULL,
			upstream_server_id bigint(20) NOT NULL,
			PRIMARY KEY (route_id, upstream_server_id),
			KEY idx_site_origin_route_upstreams_upstream (upstream_server_id),
			CONSTRAINT site_origin_route_upstreams_route_fk FOREIGN KEY (route_id) REFERENCES site_origin_routes (id) ON DELETE CASCADE ON UPDATE CASCADE,
			CONSTRAINT site_origin_route_upstreams_upstream_fk FOREIGN KEY (upstream_server_id) REFERENCES upstream_servers (id) ON DELETE CASCADE ON UPDATE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
	}
	for _, statement := range statements {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return store.backfillDefaults(ctx)
}

func (store *siteOriginRouteStore) backfillDefaults(ctx context.Context) error {
	statements := []string{
		`INSERT INTO site_origin_routes (site_id, scheme, description)
		SELECT DISTINCT s.id, UPPER(lp.protocol), 'Migrated default route'
		FROM sites s
		INNER JOIN site_listening_ports slp ON slp.site_id = s.id
		INNER JOIN listening_ports lp ON lp.id = slp.listening_port_id
		WHERE NOT EXISTS (
			SELECT 1 FROM site_origin_routes r WHERE r.site_id = s.id AND r.scheme = UPPER(lp.protocol)
		)`,
		`INSERT INTO site_origin_route_ports (route_id, site_id, scheme, port)
		SELECT r.id, r.site_id, r.scheme, lp.port
		FROM site_origin_routes r
		INNER JOIN (
			SELECT DISTINCT slp.site_id, UPPER(lp.protocol) AS scheme, lp.port
			FROM site_listening_ports slp
			INNER JOIN listening_ports lp ON lp.id = slp.listening_port_id
		) lp ON lp.site_id = r.site_id AND lp.scheme = r.scheme
		WHERE NOT EXISTS (
			SELECT 1 FROM site_origin_route_ports p
			WHERE p.site_id = r.site_id AND p.scheme = r.scheme AND p.port = lp.port
		)`,
		`INSERT INTO site_origin_route_upstreams (route_id, upstream_server_id)
		SELECT r.id, u.id
		FROM site_origin_routes r
		INNER JOIN upstream_servers u ON u.site_id = r.site_id
		WHERE NOT EXISTS (
			SELECT 1 FROM site_origin_route_upstreams ru
			WHERE ru.route_id = r.id AND ru.upstream_server_id = u.id
		)`,
		`INSERT INTO site_origin_routes (site_id, scheme, description)
		SELECT DISTINCT u.site_id, 'HTTP', 'Migrated default route'
		FROM upstream_servers u
		WHERE NOT EXISTS (
			SELECT 1 FROM site_origin_routes r WHERE r.site_id = u.site_id
		)`,
		`INSERT INTO site_origin_route_upstreams (route_id, upstream_server_id)
		SELECT r.id, u.id
		FROM site_origin_routes r
		INNER JOIN upstream_servers u ON u.site_id = r.site_id
		WHERE NOT EXISTS (
			SELECT 1 FROM site_origin_route_upstreams ru
			WHERE ru.route_id = r.id AND ru.upstream_server_id = u.id
		)`,
	}
	for _, statement := range statements {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func ValidateSiteOriginRoutes(routes SiteOriginRoutes, validUpstreamIDs map[int64]struct{}) error {
	validate := func(scheme string, rules []SiteOriginRouteRule) error {
		seenPorts := make(map[int]struct{})
		for i, rule := range rules {
			if len(rule.Ports) == 0 {
				return fmt.Errorf("%s rule %d: at least one listen port is required", strings.ToLower(scheme), i+1)
			}
			if len(rule.UpstreamIDs) == 0 {
				return fmt.Errorf("%s rule %d: at least one origin is required", strings.ToLower(scheme), i+1)
			}
			ports := uniquePositiveInts(rule.Ports)
			if len(ports) != len(rule.Ports) {
				return fmt.Errorf("%s rule %d: duplicate listen ports in the same rule", strings.ToLower(scheme), i+1)
			}
			for _, port := range ports {
				if port < 1 || port > 65535 {
					return fmt.Errorf("%s rule %d: invalid port %d", strings.ToLower(scheme), i+1, port)
				}
				if _, ok := seenPorts[port]; ok {
					return fmt.Errorf("%s listen port %d is used by more than one rule", strings.ToLower(scheme), port)
				}
				seenPorts[port] = struct{}{}
			}
			upstreams := uniquePositiveInt64s(rule.UpstreamIDs)
			if len(upstreams) != len(rule.UpstreamIDs) {
				return fmt.Errorf("%s rule %d: duplicate origin ids", strings.ToLower(scheme), i+1)
			}
			for _, id := range upstreams {
				if _, ok := validUpstreamIDs[id]; !ok {
					return fmt.Errorf("%s rule %d: origin %d does not belong to this site", strings.ToLower(scheme), i+1, id)
				}
			}
		}
		return nil
	}
	if err := validate("HTTP", routes.HTTP); err != nil {
		return err
	}
	return validate("HTTPS", routes.HTTPS)
}

func NormalizeSiteOriginRoutes(routes SiteOriginRoutes) SiteOriginRoutes {
	normalize := func(rules []SiteOriginRouteRule) []SiteOriginRouteRule {
		if rules == nil {
			return []SiteOriginRouteRule{}
		}
		out := make([]SiteOriginRouteRule, 0, len(rules))
		for _, rule := range rules {
			out = append(out, SiteOriginRouteRule{
				ID:          rule.ID,
				Ports:       uniquePositiveInts(rule.Ports),
				UpstreamIDs: uniquePositiveInt64s(rule.UpstreamIDs),
			})
		}
		return out
	}
	return SiteOriginRoutes{
		HTTP:  normalize(routes.HTTP),
		HTTPS: normalize(routes.HTTPS),
	}
}

func (store *siteOriginRouteStore) GetBySite(ctx context.Context, siteID int64) (SiteOriginRoutes, error) {
	out := SiteOriginRoutes{HTTP: []SiteOriginRouteRule{}, HTTPS: []SiteOriginRouteRule{}}
	if siteID <= 0 {
		return out, errNotFound
	}

	rows, err := store.db.QueryContext(ctx, `
		SELECT id, scheme
		FROM site_origin_routes
		WHERE site_id = ?
		ORDER BY scheme ASC, id ASC`, siteID)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	type routeMeta struct {
		id     int64
		scheme string
	}
	metas := make([]routeMeta, 0)
	for rows.Next() {
		var meta routeMeta
		if err := rows.Scan(&meta.id, &meta.scheme); err != nil {
			return out, err
		}
		meta.scheme = NormalizeOriginRouteScheme(meta.scheme)
		metas = append(metas, meta)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(metas) == 0 {
		return out, nil
	}

	portsByRoute := make(map[int64][]int, len(metas))
	portRows, err := store.db.QueryContext(ctx, `
		SELECT route_id, port
		FROM site_origin_route_ports
		WHERE site_id = ?
		ORDER BY port ASC`, siteID)
	if err != nil {
		return out, err
	}
	defer portRows.Close()
	for portRows.Next() {
		var routeID int64
		var port int
		if err := portRows.Scan(&routeID, &port); err != nil {
			return out, err
		}
		portsByRoute[routeID] = append(portsByRoute[routeID], port)
	}
	if err := portRows.Err(); err != nil {
		return out, err
	}

	upstreamsByRoute := make(map[int64][]int64, len(metas))
	upRows, err := store.db.QueryContext(ctx, `
		SELECT ru.route_id, ru.upstream_server_id
		FROM site_origin_route_upstreams ru
		INNER JOIN site_origin_routes r ON r.id = ru.route_id
		WHERE r.site_id = ?
		ORDER BY ru.upstream_server_id ASC`, siteID)
	if err != nil {
		return out, err
	}
	defer upRows.Close()
	for upRows.Next() {
		var routeID, upstreamID int64
		if err := upRows.Scan(&routeID, &upstreamID); err != nil {
			return out, err
		}
		upstreamsByRoute[routeID] = append(upstreamsByRoute[routeID], upstreamID)
	}
	if err := upRows.Err(); err != nil {
		return out, err
	}

	for _, meta := range metas {
		rule := SiteOriginRouteRule{
			ID:          meta.id,
			Ports:       portsByRoute[meta.id],
			UpstreamIDs: upstreamsByRoute[meta.id],
		}
		if rule.Ports == nil {
			rule.Ports = []int{}
		}
		if rule.UpstreamIDs == nil {
			rule.UpstreamIDs = []int64{}
		}
		if meta.scheme == "HTTPS" {
			out.HTTPS = append(out.HTTPS, rule)
		} else {
			out.HTTP = append(out.HTTP, rule)
		}
	}
	return out, nil
}

func (store *siteOriginRouteStore) ReplaceForSite(ctx context.Context, siteID int64, routes SiteOriginRoutes) (SiteOriginRoutes, error) {
	if siteID <= 0 {
		return SiteOriginRoutes{}, errNotFound
	}
	routes = NormalizeSiteOriginRoutes(routes)

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return SiteOriginRoutes{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM site_origin_routes WHERE site_id = ?`, siteID); err != nil {
		return SiteOriginRoutes{}, err
	}

	insertScheme := func(scheme string, rules []SiteOriginRouteRule) error {
		for _, rule := range rules {
			result, err := tx.ExecContext(ctx, `
				INSERT INTO site_origin_routes (site_id, scheme, description)
				VALUES (?, ?, '')`, siteID, scheme)
			if err != nil {
				return err
			}
			routeID, err := result.LastInsertId()
			if err != nil {
				return err
			}
			for _, port := range rule.Ports {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO site_origin_route_ports (route_id, site_id, scheme, port)
					VALUES (?, ?, ?, ?)`, routeID, siteID, scheme, port); err != nil {
					return err
				}
			}
			for _, upstreamID := range rule.UpstreamIDs {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO site_origin_route_upstreams (route_id, upstream_server_id)
					VALUES (?, ?)`, routeID, upstreamID); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := insertScheme("HTTP", routes.HTTP); err != nil {
		return SiteOriginRoutes{}, err
	}
	if err := insertScheme("HTTPS", routes.HTTPS); err != nil {
		return SiteOriginRoutes{}, err
	}
	if err := tx.Commit(); err != nil {
		return SiteOriginRoutes{}, err
	}
	return store.GetBySite(ctx, siteID)
}

func uniquePositiveInts(values []int) []int {
	seen := make(map[int]struct{}, len(values))
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

func uniquePositiveInt64s(values []int64) []int64 {
	seen := make(map[int64]struct{}, len(values))
	out := make([]int64, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
