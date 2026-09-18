package api

import (
	"net/http"
	"testing"
)

func TestIsPublicAuthPath(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodGet, "/health", true},
		{http.MethodGet, "/api/v1/health", true},
		{http.MethodPost, "/auth/login", true},
		{http.MethodPost, "/api/v1/auth/login", true},
		{http.MethodGet, "/api/v1/auth/oauth/providers", true},
		{http.MethodGet, "/api/v1/auth/oauth/google/start", true},
		{http.MethodGet, "/api/v1/auth/oauth/google/callback", true},
		{http.MethodPost, "/report_xdp", true},
		{http.MethodGet, "/api/get_blocklist_ips", true},
		{http.MethodPost, "/auth/logout", false},
		{http.MethodGet, "/dashboard/summary", false},
		{http.MethodGet, "/users", false},
		{http.MethodGet, "/api/v1/auth/api-tokens", false},
	}
	for _, tc := range cases {
		got := isPublicAuthPath(tc.method, tc.path)
		if got != tc.want {
			t.Fatalf("%s %s: got %v want %v", tc.method, tc.path, got, tc.want)
		}
	}
}
