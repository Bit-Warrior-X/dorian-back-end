package api

import (
	"reflect"
	"testing"

	"vue-project-backend/internal/store"
)

func TestViewerScopeUnrestrictedSeesEverything(t *testing.T) {
	var viewer viewerScope
	if !viewer.canSeeServer(42) || !viewer.canSeeSite(store.Site{ServerIDs: []int64{9}}) {
		t.Fatal("zero viewer scope must be unrestricted")
	}
	list := []store.ServerView{{ID: 1}, {ID: 2}}
	if got := viewer.filterServers(list); len(got) != 2 {
		t.Fatalf("filterServers = %d items, want 2", len(got))
	}
}

func TestViewerScopeRestrictsToAssignedEdges(t *testing.T) {
	viewer := newViewerScope([]int64{1, 1, 3})
	if !reflect.DeepEqual(viewer.serverIDs, []int64{1, 3}) {
		t.Fatalf("serverIDs = %v", viewer.serverIDs)
	}
	if viewer.canSeeServer(2) || !viewer.canSeeServer(3) {
		t.Fatal("canSeeServer mismatch")
	}

	servers := viewer.filterServers([]store.ServerView{{ID: 1}, {ID: 2}, {ID: 3}})
	if len(servers) != 2 || servers[0].ID != 1 || servers[1].ID != 3 {
		t.Fatalf("filterServers = %+v", servers)
	}

	sites := viewer.filterSites([]store.Site{
		{ID: 10, ServerIDs: []int64{1, 2}, Servers: []string{"edge-1", "edge-2"}},
		{ID: 11, ServerIDs: []int64{2}, Servers: []string{"edge-2"}},
		{ID: 12, ServerIDs: nil},
	})
	if len(sites) != 1 || sites[0].ID != 10 {
		t.Fatalf("filterSites = %+v", sites)
	}
	if !reflect.DeepEqual(sites[0].ServerIDs, []int64{1}) || !reflect.DeepEqual(sites[0].Servers, []string{"edge-1"}) {
		t.Fatalf("shared site must hide other edges, got %+v", sites[0])
	}

	if got := viewer.visibleServerIDs([]int64{1, 2, 3}); !reflect.DeepEqual(got, []int64{1, 3}) {
		t.Fatalf("visibleServerIDs = %v", got)
	}
}

func TestViewerScopeWithoutEdgesSeesNothing(t *testing.T) {
	viewer := newViewerScope(nil)
	if !viewer.restricted || viewer.canSeeServer(1) {
		t.Fatal("user without edges must not see any edge")
	}
}

func TestLeadingPathID(t *testing.T) {
	cases := map[string]int64{
		"/servers/12/host-metrics": 12,
		"/api/v1/servers/7":        7,
		"/sites/5/cache-rules/1":   5,
		"/servers/blacklist":       0,
		"/servers":                 0,
	}
	for path, want := range cases {
		collection := "servers"
		if path == "/sites/5/cache-rules/1" {
			collection = "sites"
		}
		if got := leadingPathID(path, collection); got != want {
			t.Errorf("leadingPathID(%q) = %d, want %d", path, got, want)
		}
	}
}
