package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

func TestEdgeSignatureRoundTrip(t *testing.T) {
	body := []byte(`{"server_id":7}`)
	req := httptest.NewRequest(http.MethodPost, "http://10.0.0.1:5000/API/L7/l7_update_site", nil)
	now := time.Unix(1_800_000_000, 0)
	signEdgeRequest(req, "edge-token", body, now)

	if err := verifyEdgeSignature("edge-token", req.Method, req.URL.Path, req.Header, body, now.Add(time.Minute)); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	cases := map[string]func() error{
		"wrong token": func() error {
			return verifyEdgeSignature("other", req.Method, req.URL.Path, req.Header, body, now)
		},
		"tampered body": func() error {
			return verifyEdgeSignature("edge-token", req.Method, req.URL.Path, req.Header, []byte(`{"server_id":8}`), now)
		},
		"different path": func() error {
			return verifyEdgeSignature("edge-token", req.Method, "/API/L7/l7_delete_site", req.Header, body, now)
		},
		"replayed later": func() error {
			return verifyEdgeSignature("edge-token", req.Method, req.URL.Path, req.Header, body, now.Add(10*time.Minute))
		},
		"missing headers": func() error {
			return verifyEdgeSignature("edge-token", req.Method, req.URL.Path, http.Header{}, body, now)
		},
	}
	for name, check := range cases {
		if check() == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestNewL7EdgeRequestSignsAndHonoursAgentConfig(t *testing.T) {
	var got *http.Request
	var gotBody []byte
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer edge.Close()

	host, port, _ := strings.Cut(strings.TrimPrefix(edge.URL, "http://"), ":")
	configureL7Edge(config.Config{AgentScheme: "http", AgentPort: port})
	t.Cleanup(func() { configureL7Edge(config.Config{AgentScheme: "http", AgentPort: "5000"}) })

	body := []byte(`{"site_id":1}`)
	req, err := newL7EdgeRequest(context.Background(), store.ServerView{IP: host, Token: "tok-1"}, "/API/L7/l7_update_site", body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := l7EdgeClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got == nil || got.URL.Path != "/API/L7/l7_update_site" {
		t.Fatalf("edge did not receive the request: %+v", got)
	}
	if strings.Contains(got.Header.Get(edgeSignatureHeader)+got.Header.Get("Authorization"), "tok-1") {
		t.Fatal("edge token must not be sent in clear")
	}
	if err := verifyEdgeSignature("tok-1", got.Method, got.URL.Path, got.Header, gotBody, time.Now()); err != nil {
		t.Fatalf("edge-side verification failed: %v", err)
	}
}
