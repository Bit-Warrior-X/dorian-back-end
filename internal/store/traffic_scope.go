package store

import (
	"fmt"
	"strings"
)

// TrafficScope narrows analytics to an edge node and/or site.
// SiteID filters L7 site-scoped tables (dimensions, site_traffic_stats, domain_request_stats).
// NIC / L4 remain server-scoped and only use ServerID / ServerIDs.
type TrafficScope struct {
	ServerID  int64
	ServerIDs []int64
	SiteID    int64
	Domain    string
}

func appendServerScope(query string, args []any, scope TrafficScope) (string, []any) {
	if scope.ServerID > 0 {
		return query + " AND server_id = ?", append(args, scope.ServerID)
	}
	if len(scope.ServerIDs) == 0 {
		return query, args
	}
	placeholders := make([]string, len(scope.ServerIDs))
	for i, id := range scope.ServerIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	return query + fmt.Sprintf(" AND server_id IN (%s)", strings.Join(placeholders, ",")), args
}

// appendTrafficScope applies server filters and optional site_id for site-scoped tables.
func appendTrafficScope(query string, args []any, scope TrafficScope, includeSite bool) (string, []any) {
	query, args = appendServerScope(query, args, scope)
	if includeSite && scope.SiteID > 0 {
		query += " AND site_id = ?"
		args = append(args, scope.SiteID)
	}
	return query, args
}

// l7StatsTable returns the L7 aggregate table for the scope.
// When a site is selected, prefer site_traffic_stats (no NIC columns).
func l7StatsTable(scope TrafficScope) string {
	if scope.SiteID > 0 {
		return "site_traffic_stats"
	}
	return "server_traffic_stats"
}

// usesSiteTraffic is true when L7 aggregates should read site_traffic_stats.
func usesSiteTraffic(scope TrafficScope) bool {
	return scope.SiteID > 0
}
