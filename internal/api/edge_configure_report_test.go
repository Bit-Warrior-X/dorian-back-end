package api

import (
	"testing"

	"vue-project-backend/internal/store"
)

func TestApplyFirewallConfigMap(t *testing.T) {
	cfg := store.L4Config{
		Dev:          "lo",
		SynThreshold: 1,
	}
	applyFirewallConfigMap(&cfg, map[string]string{
		"dev":                       "eth0",
		"attach_mode":               "native",
		"syn_valid":                 "1",
		"syn_threshold":             "100000",
		"ackValid":                  "true",
		"geo_allow_countries":       "US, CA;GB",
		"tcp_connection_limit_check": "yes",
		"tcp_connection_limit_cnt":  "5000",
	})

	if cfg.Dev != "eth0" {
		t.Fatalf("dev: got %q", cfg.Dev)
	}
	if cfg.AttachMode != "native" {
		t.Fatalf("attachMode: got %q", cfg.AttachMode)
	}
	if !cfg.SynValid {
		t.Fatal("synValid expected true")
	}
	if cfg.SynThreshold != 100000 {
		t.Fatalf("synThreshold: got %d", cfg.SynThreshold)
	}
	if !cfg.AckValid {
		t.Fatal("ackValid expected true")
	}
	if len(cfg.GeoAllowCountries) != 3 {
		t.Fatalf("geo countries: got %#v", cfg.GeoAllowCountries)
	}
	if !cfg.TcpConnectionLimitCheck || cfg.TcpConnectionLimitCnt != 5000 {
		t.Fatalf("tcp limit: %#v %d", cfg.TcpConnectionLimitCheck, cfg.TcpConnectionLimitCnt)
	}
}
