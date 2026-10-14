package api

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPFromRequest(t *testing.T) {
	cases := []struct {
		name    string
		remote  string
		headers map[string]string
		want    string
	}{
		{
			name:    "direct client cannot spoof forwarding headers",
			remote:  "203.0.113.9:5555",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "1.2.3.4"},
			want:    "203.0.113.9",
		},
		{
			name:    "local proxy X-Real-IP is trusted",
			remote:  "127.0.0.1:40000",
			headers: map[string]string{"X-Real-IP": "198.51.100.7", "X-Forwarded-For": "6.6.6.6, 198.51.100.7"},
			want:    "198.51.100.7",
		},
		{
			name:    "local proxy falls back to right-most forwarded entry",
			remote:  "[::1]:40000",
			headers: map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.8"},
			want:    "198.51.100.8",
		},
		{
			name:    "garbage header from proxy is ignored",
			remote:  "127.0.0.1:40000",
			headers: map[string]string{"X-Real-IP": "not-an-ip"},
			want:    "127.0.0.1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/auth/login", nil)
			r.RemoteAddr = tc.remote
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := clientIPFromRequest(r); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
