package api

import (
	"net/http"
	"strings"
)

type apiTokenScopeInfo struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// apiTokenScopeCatalog is the set of scopes a token may carry. Write implies read
// for the same area. Account endpoints (tokens, sessions, 2FA, users, audit,
// settings) are reachable only with "*".
var apiTokenScopeCatalog = []apiTokenScopeInfo{
	{ID: "*", Label: "Full access", Description: "Everything your account can do, including account settings."},
	{ID: "read", Label: "Read only", Description: "GET requests on edges, sites, WAF, and analytics."},
	{ID: "analytics:read", Label: "Analytics", Description: "Dashboard, analytics, and access logs."},
	{ID: "edges:read", Label: "Edges · read", Description: "List edges, status, ports, and L4 settings."},
	{ID: "edges:write", Label: "Edges · write", Description: "Create, configure, upgrade, and delete edges."},
	{ID: "sites:read", Label: "Sites · read", Description: "List sites, origins, SSL, cache, and ports."},
	{ID: "sites:write", Label: "Sites · write", Description: "Create, configure, and delete sites."},
	{ID: "waf:read", Label: "WAF · read", Description: "WAF rule sets and temporary blocks."},
	{ID: "waf:write", Label: "WAF · write", Description: "Edit WAF rule sets and temporary blocks."},
}

func isKnownAPITokenScope(scope string) bool {
	for _, item := range apiTokenScopeCatalog {
		if item.ID == scope {
			return true
		}
	}
	return false
}

// apiAreaForPath maps a request path to the scope area that guards it.
// An empty result means account-level (full access only).
func apiAreaForPath(path string) string {
	p := strings.TrimSuffix(path, "/")
	p = strings.TrimPrefix(p, "/api/v1")
	p = strings.TrimPrefix(p, "/api")
	switch {
	case p == "/analytics" || strings.HasPrefix(p, "/analytics/"),
		p == "/dashboard" || strings.HasPrefix(p, "/dashboard/"),
		strings.HasSuffix(p, "/access-log/stream"):
		return "analytics"
	case p == "/servers/blacklist" || strings.HasPrefix(p, "/servers/blacklist/"):
		return "waf"
	case p == "/servers" || strings.HasPrefix(p, "/servers/"),
		p == "/license-plans", p == "/deploy-versions":
		return "edges"
	case p == "/sites" || strings.HasPrefix(p, "/sites/"):
		return "sites"
	case p == "/waf-rules" || strings.HasPrefix(p, "/waf-rules/"):
		return "waf"
	default:
		return ""
	}
}

func isReadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// apiTokenAllows reports whether scopes permit method on path.
func apiTokenAllows(scopes []string, method, path string) bool {
	has := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		has[strings.TrimSpace(scope)] = true
	}
	if has["*"] {
		return true
	}
	area := apiAreaForPath(path)
	if area == "" {
		return false
	}
	read := isReadMethod(method)
	if has[area+":write"] {
		return true
	}
	if !read {
		return false
	}
	return has["read"] || has[area+":read"]
}
