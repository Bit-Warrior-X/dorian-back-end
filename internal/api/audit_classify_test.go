package api

import (
	"context"
	"reflect"
	"testing"
)

func TestClassifyAuditRequest(t *testing.T) {
	tests := []struct {
		method, path            string
		log                     bool
		action, category, rtype string
		id                      int64
		summary                 string
	}{
		{"GET", "/servers/5", false, "", "", "", 0, ""},
		{"POST", "/servers/5/refresh-runtime-status", false, "", "", "", 0, ""},
		{"POST", "/servers", true, "create", "edge", "edge", 0, "Create edge {target}"},
		{"PUT", "/api/v1/servers/5", true, "update", "edge", "edge", 5, "Update edge {target}"},
		{"PUT", "/servers/5/users", true, "assign", "edge", "edge", 5, "Change management users of edge {target}"},
		{"POST", "/servers/5/upgrade", true, "upgrade", "edge", "edge", 5, "Upgrade Angelos on edge {target}"},
		{"POST", "/servers/5/listening-ports", true, "create", "listening_port", "edge", 5, "Add listening port to edge {target}"},
		{"DELETE", "/servers/5/listening-ports/9", true, "delete", "listening_port", "edge", 5, "Remove listening port #9 from edge {target}"},
		{"POST", "/servers/5/l4/blacklist/clear", true, "delete", "l4", "edge", 5, "Clear the L4 blocklist on edge {target}"},
		{"POST", "/servers/5/l4/whitelist/remove/1.2.3.4", true, "delete", "l4", "edge", 5, "Remove 1.2.3.4 from the L4 allowlist on edge {target}"},
		{"POST", "/servers/blacklist", true, "create", "blacklist", "blacklist", 0, "Add entry to blocked list"},
		{"PUT", "/users/7", true, "update", "user", "user", 7, "Update user {target}"},
		{"DELETE", "/users/7/mfa", true, "mfa_reset", "auth", "user", 7, "Reset two-factor authentication for user {target}"},
		{"POST", "/auth/mfa/enable", true, "mfa_enable", "auth", "user", 0, "Enable two-factor authentication"},
		{"POST", "/auth/mfa/setup", false, "", "", "", 0, ""},
		{"POST", "/auth/api-tokens", true, "token_create", "api_token", "api_token", 0, "Create API token {target}"},
		{"DELETE", "/auth/api-tokens/3", true, "token_revoke", "api_token", "api_token", 3, "Revoke API token {target}"},
		{"POST", "/auth/login", false, "", "", "", 0, ""},
		{"POST", "/sites/2/cache-rules/clear-cache", true, "operate", "cache", "site", 2, "Purge all cached content for site {target}"},
		{"PUT", "/sites/2/cache-rules/4", true, "update", "cache", "site", 2, "Update cache rule #4 of site {target}"},
		{"POST", "/sites/2/waf/geolocation", true, "create", "waf", "site", 2, "Add geo blocking entry to site {target}"},
		{"DELETE", "/sites/2/waf/whitelist/8", true, "delete", "waf", "site", 2, "Remove IP allowlist entry #8 from site {target}"},
		{"POST", "/sites/2/certificate/renew", true, "operate", "certificate", "site", 2, "Request certificate renewal for site {target}"},
		{"POST", "/waf-rules/3/duplicate", true, "duplicate", "waf_rule", "waf_rule", 3, "Duplicate WAF rule set {target}"},
		{"PUT", "/waf-rules/3/waf/anti-cc/1", true, "update", "waf", "waf_rule", 3, "Update anti-CC entry #1 of WAF rule set {target}"},
	}
	for _, tt := range tests {
		got := classifyAuditRequest(tt.method, tt.path)
		if got.ShouldLog != tt.log {
			t.Errorf("%s %s: ShouldLog=%v want %v", tt.method, tt.path, got.ShouldLog, tt.log)
			continue
		}
		if !tt.log {
			continue
		}
		if got.Action != tt.action || got.Category != tt.category || got.ResourceType != tt.rtype ||
			got.ResourceID != tt.id || got.Summary != tt.summary {
			t.Errorf("%s %s: got action=%q category=%q type=%q id=%d summary=%q",
				tt.method, tt.path, got.Action, got.Category, got.ResourceType, got.ResourceID, got.Summary)
		}
	}
}

func TestClassifyAuditDescribe(t *testing.T) {
	control := classifyAuditRequest("POST", "/servers/5/service-control")
	if got := control.Describe(map[string]any{"service": "athens", "action": "stop"}); got != "Stop Athens (L7) service on edge {target}" {
		t.Fatalf("service-control summary = %q", got)
	}
	power := classifyAuditRequest("POST", "/servers/5/host-power")
	if got := power.Describe(map[string]any{"action": "poweroff"}); got != "Power off the host of edge {target}" {
		t.Fatalf("host-power summary = %q", got)
	}
}

func TestConjugateAuditSummary(t *testing.T) {
	cases := map[string][2]string{
		"Delete user {target}":                      {"Deleted user {target}", "Failed to delete user {target}"},
		"Power off the host of edge {target}":       {"Powered off the host of edge {target}", "Failed to power off the host of edge {target}"},
		"Reset two-factor authentication":           {"Reset two-factor authentication", "Failed to reset two-factor authentication"},
		"Stop Athens (L7) service on edge {target}": {"Stopped Athens (L7) service on edge {target}", "Failed to stop Athens (L7) service on edge {target}"},
	}
	for in, want := range cases {
		if got := conjugateAuditSummary(in, true); got != want[0] {
			t.Errorf("success %q = %q", in, got)
		}
		if got := conjugateAuditSummary(in, false); got != want[1] {
			t.Errorf("failure %q = %q", in, got)
		}
	}
}

func TestAuditDiffLines(t *testing.T) {
	res := &auditResolver{}
	before := map[string]any{"name": "edge-1", "ip": "10.0.0.1", "sshPassword": "old", "sshPort": "22", "status": "Running"}
	after := map[string]any{"name": "edge-1", "ip": "10.0.0.2", "sshPassword": "new", "sshPort": "22", "status": "Stopped"}
	body := map[string]any{"name": "edge-1", "ip": "10.0.0.2", "sshPassword": "new", "sshPort": "22"}

	got := res.diffLines(context.Background(), before, after, body, nil)
	want := []string{"IP: 10.0.0.1 → 10.0.0.2", "SSH password: changed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("diffLines = %#v, want %#v", got, want)
	}

	userBefore := map[string]any{"role": "User", "status": "Active"}
	userAfter := map[string]any{"role": "Admin", "status": "Active"}
	got = res.diffLines(context.Background(), userBefore, userAfter,
		map[string]any{"role": "Admin", "status": "Active", "password": "secret", "currentPassword": "x"}, nil)
	want = []string{"Role: User → Admin", "Password: changed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("user diffLines = %#v, want %#v", got, want)
	}
}

func TestAuditValueLinesMasksSecrets(t *testing.T) {
	res := &auditResolver{}
	got := res.valueLines(context.Background(), map[string]any{
		"name": "edge-1", "ip": "10.0.0.1", "sshPassword": "hunter2", "licenseFile": "BLOB", "sshPort": "", "enabled": true,
	})
	want := []string{"Name: edge-1", "IP: 10.0.0.1", "Enabled: yes", "License file: provided", "SSH password: provided"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("valueLines = %#v, want %#v", got, want)
	}
}
