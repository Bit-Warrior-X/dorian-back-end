package api

import (
	"testing"
	"time"

	"vue-project-backend/internal/store"
)

func TestResolveL4AttackPeak(t *testing.T) {
	drops := []attackDropPoint{
		{Timestamp: "2026-11-04T01:00:00Z", Blocked: 100, Allowed: 50},
		{Timestamp: "2026-11-04T01:00:05Z", Blocked: 900, Allowed: 100},
		{Timestamp: "2026-11-04T01:00:10Z", Blocked: 200, Allowed: 20},
	}
	peak := resolveL4AttackPeak(drops)
	if peak == nil {
		t.Fatal("expected peak")
	}
	if peak.Layer != "L4" || peak.Metric != "ingress_bytes" {
		t.Fatalf("unexpected peak identity: %+v", peak)
	}
	if peak.Value != 1000 {
		t.Fatalf("value=%v want 1000", peak.Value)
	}
	if peak.At != "2026-11-04T01:00:05Z" {
		t.Fatalf("at=%q", peak.At)
	}
	if peak.BlockedShare < 0.89 || peak.BlockedShare > 0.91 {
		t.Fatalf("blockedShare=%v", peak.BlockedShare)
	}
}

func TestResolveL7AttackPeakUsesIncident(t *testing.T) {
	l7 := &store.L7AttackIncident{
		PeakRPS:      125000,
		PeakRPSAt:    time.Date(2026, 11, 4, 1, 12, 33, 0, time.UTC).Unix(),
		BlockedRatio: 0.82,
	}
	peak := resolveL7AttackPeak(nil, l7)
	if peak.Value != 125000 {
		t.Fatalf("value=%v", peak.Value)
	}
	if peak.At != "2026-11-04T01:12:33Z" {
		t.Fatalf("at=%q", peak.At)
	}
	if peak.BlockedShare != 0.82 {
		t.Fatalf("blockedShare=%v", peak.BlockedShare)
	}
}

func TestResolveL7AttackPeakUsesMitigatedTotals(t *testing.T) {
	// Malformed floods report blocked_ratio=0 (IP blocks only) while most
	// requests are rejected as malformed. Console share must include those.
	l7 := &store.L7AttackIncident{
		PeakRPS:      537,
		PeakRPSAt:    time.Date(2026, 11, 11, 9, 36, 4, 0, time.UTC).Unix(),
		BlockedRatio: 0,
		Totals: map[string]any{
			"requests":    float64(24000),
			"passed":      float64(513),
			"blocked":     float64(0),
			"malformed":   float64(23000),
			"rapid_reset": float64(487),
		},
	}
	peak := resolveL7AttackPeak(nil, l7)
	if peak.Value != 537 {
		t.Fatalf("value=%v", peak.Value)
	}
	want := (23000.0 + 487.0) / 24000.0
	if peak.BlockedShare < want-0.001 || peak.BlockedShare > want+0.001 {
		t.Fatalf("blockedShare=%v want ~%v", peak.BlockedShare, want)
	}
}

func TestLoadL7DropSeriesIncludesMalformed(t *testing.T) {
	incident := &store.L7AttackIncident{
		Timeline: []map[string]any{
			{
				"t":           float64(1000),
				"requests":    float64(5370),
				"passed":      float64(40),
				"blocked":     float64(0),
				"malformed":   float64(5300),
				"rapid_reset": float64(30),
			},
			{
				"t":        float64(1010),
				"requests": float64(100),
				"passed":   float64(100),
				"blocked":  float64(0),
			},
		},
	}
	drops := loadL7DropSeries(incident)
	if len(drops) != 2 {
		t.Fatalf("len=%d", len(drops))
	}
	if drops[0].Blocked != 5330 {
		t.Fatalf("bucket0 blocked=%d want 5330 (malformed+rapid_reset)", drops[0].Blocked)
	}
	if drops[0].Allowed != 40 {
		t.Fatalf("bucket0 allowed=%d", drops[0].Allowed)
	}
	if drops[1].Blocked != 0 || drops[1].Allowed != 100 {
		t.Fatalf("bucket1=%+v", drops[1])
	}
}

func TestAttackHostSampleWindowStaysInsideAttack(t *testing.T) {
	period := store.SecurityEventPeriod{
		StartedAt: "2026-11-13T03:17:37Z",
		EndedAt:   "2026-11-13T03:19:59Z",
		Status:    "ended",
	}
	peakAt := time.Date(2026, 11, 13, 3, 19, 0, 0, time.UTC)
	start, end := attackHostSampleWindow(period, nil, peakAt, false)
	if start.After(peakAt) || end.Before(peakAt) {
		t.Fatalf("window [%s, %s] excludes peak %s", start, end, peakAt)
	}
	// Post-attack quiet sample at 03:23 must stay outside the window.
	quiet := time.Date(2026, 11, 13, 3, 23, 0, 0, time.UTC)
	if !quiet.After(end) {
		t.Fatalf("window end %s still includes quiet sample %s", end, quiet)
	}
	wantStart := time.Date(2026, 11, 13, 3, 16, 37, 0, time.UTC)
	wantEnd := time.Date(2026, 11, 13, 3, 20, 59, 0, time.UTC)
	if !start.Equal(wantStart) || !end.Equal(wantEnd) {
		t.Fatalf("window=%s..%s want %s..%s", start, end, wantStart, wantEnd)
	}
}

func TestL7TotalsRequestsBlockedIncludesMalformed(t *testing.T) {
	req, blocked := l7TotalsRequestsBlocked(map[string]any{
		"requests":  float64(1000),
		"passed":    float64(50),
		"blocked":   float64(10),
		"malformed": float64(900),
	})
	if req != 1000 || blocked != 910 {
		t.Fatalf("req=%d blocked=%d", req, blocked)
	}
}
