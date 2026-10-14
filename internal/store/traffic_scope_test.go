package store

import (
	"reflect"
	"testing"
)

func TestAppendServerScope(t *testing.T) {
	cases := []struct {
		name  string
		scope TrafficScope
		query string
		args  []any
	}{
		{"unrestricted all", TrafficScope{}, "Q", nil},
		{"restricted without edges", TrafficScope{Restricted: true}, "Q AND 1 = 0", nil},
		{"restricted edges", TrafficScope{Restricted: true, ServerIDs: []int64{3, 4}}, "Q AND server_id IN (?,?)", []any{int64(3), int64(4)}},
		{"single edge", TrafficScope{Restricted: true, ServerID: 7}, "Q AND server_id = ?", []any{int64(7)}},
	}
	for _, tc := range cases {
		query, args := appendServerScope("Q", nil, tc.scope)
		if query != tc.query || !reflect.DeepEqual(args, tc.args) {
			t.Errorf("%s: got %q %v, want %q %v", tc.name, query, args, tc.query, tc.args)
		}
	}
}

func TestAppendIDAllowList(t *testing.T) {
	if query, _ := appendIDAllowList("Q", nil, "id", nil); query != "Q AND 1 = 0" {
		t.Fatalf("empty allow-list = %q", query)
	}
	query, args := appendIDAllowList("Q", []any{"x"}, "ss.server_id", []int64{1})
	if query != "Q AND ss.server_id IN (?)" || !reflect.DeepEqual(args, []any{"x", int64(1)}) {
		t.Fatalf("allow-list = %q %v", query, args)
	}
}
