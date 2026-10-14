package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"vue-project-backend/internal/store"
)

var (
	errScopeServerNotFound = errors.New("server not found")
	errScopeSiteNotFound   = errors.New("site not found")
)

// viewerScope limits what a non-admin user can see to the edges assigned to them
// (server_users) and the sites served by those edges. The zero value is unrestricted.
type viewerScope struct {
	restricted bool
	serverIDs  []int64
	allowed    map[int64]bool
}

type viewerScopeContextKey struct{}

func newViewerScope(serverIDs []int64) viewerScope {
	scope := viewerScope{restricted: true, allowed: make(map[int64]bool, len(serverIDs))}
	for _, id := range serverIDs {
		if id > 0 && !scope.allowed[id] {
			scope.allowed[id] = true
			scope.serverIDs = append(scope.serverIDs, id)
		}
	}
	return scope
}

func viewerScopeFromContext(ctx context.Context) viewerScope {
	scope, _ := ctx.Value(viewerScopeContextKey{}).(viewerScope)
	return scope
}

func (v viewerScope) canSeeServer(id int64) bool {
	return !v.restricted || v.allowed[id]
}

func (v viewerScope) canSeeSite(site store.Site) bool {
	if !v.restricted {
		return true
	}
	for _, id := range site.ServerIDs {
		if v.allowed[id] {
			return true
		}
	}
	return false
}

// visibleServerIDs intersects ids with the viewer's edges.
func (v viewerScope) visibleServerIDs(ids []int64) []int64 {
	if !v.restricted {
		return ids
	}
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if v.allowed[id] {
			out = append(out, id)
		}
	}
	return out
}

func (v viewerScope) filterServers(list []store.ServerView) []store.ServerView {
	if !v.restricted {
		return list
	}
	out := make([]store.ServerView, 0, len(list))
	for _, server := range list {
		if v.allowed[server.ID] {
			out = append(out, server)
		}
	}
	return out
}

// filterSites drops sites the viewer cannot see and hides other users' edges on shared sites.
func (v viewerScope) filterSites(list []store.Site) []store.Site {
	if !v.restricted {
		return list
	}
	out := make([]store.Site, 0, len(list))
	for _, site := range list {
		if !v.canSeeSite(site) {
			continue
		}
		aligned := len(site.Servers) == len(site.ServerIDs)
		ids := make([]int64, 0, len(site.ServerIDs))
		names := make([]string, 0, len(site.Servers))
		for i, id := range site.ServerIDs {
			if !v.allowed[id] {
				continue
			}
			ids = append(ids, id)
			if aligned {
				names = append(names, site.Servers[i])
			}
		}
		site.ServerIDs = ids
		if aligned {
			site.Servers = names
		}
		out = append(out, site)
	}
	return out
}

func isScopeNotFound(err error) bool {
	return errors.Is(err, errScopeServerNotFound) || errors.Is(err, errScopeSiteNotFound)
}

// withViewerScope loads the assigned edges of non-admin users. It must run inside
// withAuth so the principal is known.
func withViewerScope(users store.UserStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := AuthPrincipalFromContext(r.Context())
		if !ok || principal.UserID <= 0 || strings.EqualFold(principal.Role, "Admin") {
			next.ServeHTTP(w, r)
			return
		}
		user, err := users.FindByID(r.Context(), principal.UserID)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusUnauthorized, "account not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to load account")
			return
		}
		ctx := context.WithValue(r.Context(), viewerScopeContextKey{}, newViewerScope(user.ServerIDs))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// restrictServerDetail answers 404 for /servers/{id}/… when the edge is not the viewer's.
func restrictServerDetail(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		viewer := viewerScopeFromContext(r.Context())
		if viewer.restricted {
			if id := leadingPathID(r.URL.Path, "servers"); id > 0 && !viewer.canSeeServer(id) {
				writeError(w, http.StatusNotFound, "server not found")
				return
			}
		}
		next(w, r)
	}
}

// restrictSiteDetail answers 404 for /sites/{id}/… when the site is not on the viewer's edges.
func restrictSiteDetail(sites store.SiteStore, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		viewer := viewerScopeFromContext(r.Context())
		if viewer.restricted {
			if id := leadingPathID(r.URL.Path, "sites"); id > 0 {
				site, err := sites.Get(r.Context(), id)
				if err != nil && !store.IsNotFound(err) {
					writeError(w, http.StatusInternalServerError, "failed to load site")
					return
				}
				if err != nil || !viewer.canSeeSite(site) {
					writeError(w, http.StatusNotFound, "site not found")
					return
				}
			}
		}
		next(w, r)
	}
}

// leadingPathID returns the numeric id after /<collection>/ (with or without /api/v1).
func leadingPathID(path, collection string) int64 {
	segs := strings.Split(strings.TrimPrefix(normalizeAuditPath(path), "/"), "/")
	if len(segs) < 2 || segs[0] != collection {
		return 0
	}
	return parseAuditID(segs[1])
}
