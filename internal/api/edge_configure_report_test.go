package api

import (
	"encoding/json"
	"strings"
	"testing"

	"vue-project-backend/internal/store"
)

func TestEdgeConfigureReportMixedTypesDecode(t *testing.T) {
	raw := `{
		"token":"t","command":"report_edge_configure","reported_at":1742800000,
		"l4":{
			"firewall_config":{"dev":"eth0","syn_valid":1,"syn_threshold":100000,"black_ip_duration":"3600"},
			"firewall_config_error":null,
			"blocklist":[{"ip":"198.51.100.10","duration":"600s","created":1742800100,"reason":"syn"}]
		},
		"l7":{
			"edge":{
				"listeningports":[{"port":"80","protocol":"http","status":"ENABLE"}],
				"temporaryblacklist":[{"ip":"203.0.113.9","blocked_at":1742800200,"ttl":"3600","site_id":"55"}]
			},
			"sites":{}
		}
	}`
	var payload edgeConfigureReportPayload
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cfg := flexibleStringMap(payload.L4.FirewallConfig)
	if cfg["syn_threshold"] != "100000" || cfg["syn_valid"] != "1" {
		t.Fatalf("firewall_config: %#v", cfg)
	}
	if payload.L4.Blocklist[0].Duration.Int64() != 600 {
		t.Fatalf("duration: %d", payload.L4.Blocklist[0].Duration.Int64())
	}
	if payload.L7.Edge.TemporaryBlacklist[0].BlockedAt.String() != "1742800200" {
		t.Fatalf("blocked_at: %q", payload.L7.Edge.TemporaryBlacklist[0].BlockedAt)
	}
	if payload.L7.Edge.ListeningPorts[0].Port.Int64() != 80 {
		t.Fatalf("port: %d", payload.L7.Edge.ListeningPorts[0].Port.Int64())
	}
}

func TestApplyFirewallConfigMap(t *testing.T) {
	cfg := store.L4Config{
		Dev:          "lo",
		SynThreshold: 1,
	}
	applyFirewallConfigMap(&cfg, map[string]string{
		"dev":                        "eth0",
		"attach_mode":                "native",
		"syn_valid":                  "1",
		"syn_threshold":              "100000",
		"ackValid":                   "true",
		"geo_allow_countries":        "US, CA;GB",
		"tcp_connection_limit_check": "yes",
		"tcp_connection_limit_cnt":   "5000",
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

func TestNormalizeL4EnumFields(t *testing.T) {
	cfg := store.L4Config{AttachMode: "native", Sensitivity: "Medium", ProtectionMode: "Always On"}
	applyFirewallConfigMap(&cfg, map[string]string{
		"attach_mode":     "offload", // maps to drv
		"sensitivity":     "HIGH",
		"protection_mode": "monitor",
	})
	if cfg.AttachMode != "drv" || cfg.Sensitivity != "High" || cfg.ProtectionMode != "Monitor" {
		t.Fatalf("normalized enums: %#v", cfg)
	}

	before := cfg
	applyFirewallConfigMap(&cfg, map[string]string{
		"attach_mode":     "not-a-real-mode",
		"sensitivity":     "turbo",
		"protection_mode": "banana",
	})
	if cfg.AttachMode != before.AttachMode || cfg.Sensitivity != before.Sensitivity || cfg.ProtectionMode != before.ProtectionMode {
		t.Fatalf("invalid enums should be ignored: before=%#v after=%#v", before, cfg)
	}
}
