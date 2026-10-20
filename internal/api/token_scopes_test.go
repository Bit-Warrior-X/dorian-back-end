package api

import (
	"net/http"
	"testing"
)

func TestAPITokenAllows(t *testing.T) {
	cases := []struct {
		scopes []string
		method string
		path   string
		want   bool
	}{
		{[]string{"*"}, http.MethodDelete, "/users/3", true},
		{[]string{"read"}, http.MethodGet, "/servers", true},
		{[]string{"read"}, http.MethodGet, "/api/v1/sites/4", true},
		{[]string{"read"}, http.MethodPost, "/servers", false},
		{[]string{"read"}, http.MethodGet, "/users", false},
		{[]string{"read"}, http.MethodGet, "/auth/api-tokens", false},
		{[]string{"analytics:read"}, http.MethodGet, "/analytics/summary", true},
		{[]string{"analytics:read"}, http.MethodGet, "/servers/2/access-log/stream", true},
		{[]string{"analytics:read"}, http.MethodGet, "/servers", false},
		{[]string{"edges:write"}, http.MethodGet, "/servers/2", true},
		{[]string{"edges:write"}, http.MethodPut, "/servers/2", true},
		{[]string{"edges:write"}, http.MethodPost, "/servers/blacklist", false},
		{[]string{"waf:write"}, http.MethodPost, "/servers/blacklist", true},
		{[]string{"sites:read"}, http.MethodPut, "/sites/1", false},
		{nil, http.MethodGet, "/servers", false},
	}
	for _, tc := range cases {
		if got := apiTokenAllows(tc.scopes, tc.method, tc.path); got != tc.want {
			t.Errorf("apiTokenAllows(%v, %s, %s) = %v, want %v", tc.scopes, tc.method, tc.path, got, tc.want)
		}
	}
}

func TestMFASetupAllowed(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/auth/mfa/setup", true},
		{http.MethodPost, "/api/v1/auth/mfa/enable", true},
		{http.MethodPost, "/auth/logout", true},
		{http.MethodGet, "/auth/me", true},
		{http.MethodGet, "/users/7", true},
		{http.MethodPut, "/users/7", false},
		{http.MethodGet, "/users/8", false},
		{http.MethodGet, "/servers", false},
		{http.MethodPost, "/auth/api-tokens", false},
		{http.MethodDelete, "/auth/sessions/abc", true},
	}
	for _, tc := range cases {
		if got := mfaSetupAllowed(tc.method, tc.path, 7); got != tc.want {
			t.Errorf("mfaSetupAllowed(%s, %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}
