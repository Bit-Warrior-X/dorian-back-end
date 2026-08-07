package store

import (
	"fmt"
	"strings"
)

// TrafficScope narrows analytics to an edge node and/or site (domain + linked servers).
type TrafficScope struct {
	ServerID  int64
	ServerIDs []int64
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
