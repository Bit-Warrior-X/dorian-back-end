package remotesvc

import (
	"strings"
	"testing"
)

func TestMapSystemdToRuntime(t *testing.T) {
	tests := map[string]string{
		"active":       "running",
		"reloading":    "running",
		"activating":   "stopped",
		"deactivating": "stopped",
		"failed":       "stopped",
		"inactive":     "stopped",
		"dead":         "stopped",
		"unknown":      "unknown",
		"":             "unknown",
	}

	for input, want := range tests {
		if got := mapSystemdToRuntime(input); got != want {
			t.Fatalf("mapSystemdToRuntime(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestReasonFromUnitDetails(t *testing.T) {
	got := reasonFromUnitDetails("failed", "failed", "exit-code", "1", "3", "sparta: bind failed")
	if !strings.Contains(got, "Unit failed") || !strings.Contains(got, "exit=1") {
		t.Fatalf("unexpected failed reason: %q", got)
	}
	got = reasonFromUnitDetails("inactive", "dead", "success", "0", "0", "")
	if got != "Service is inactive (stopped or not started)" && !strings.Contains(got, "inactive") {
		t.Fatalf("unexpected inactive reason: %q", got)
	}
	if got := reasonFromUnitDetails("active", "running", "success", "0", "0", ""); got != "" {
		t.Fatalf("expected empty reason for active, got %q", got)
	}
}
