package api

import (
	"net/http"
	"testing"
	"time"
)

func TestDurationDaysUntil(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		end  time.Time
		want int
	}{
		{name: "same day", end: now.Add(2 * time.Hour), want: 1},
		{name: "exact 30d", end: now.Add(30 * 24 * time.Hour), want: 30},
		{name: "30d plus one hour", end: now.Add(30*24*time.Hour + time.Hour), want: 31},
		{name: "past", end: now.Add(-time.Hour), want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := durationDaysUntil(tc.end, now); got != tc.want {
				t.Fatalf("durationDaysUntil(%v)=%d want %d", tc.end, got, tc.want)
			}
		})
	}
}

func TestSummarizeEdgeLicenseStatus(t *testing.T) {
	if got := summarizeEdgeLicenseStatus(http.StatusLocked, ""); got == "" {
		t.Fatal("expected 423 message")
	}
	if got := summarizeEdgeLicenseStatus(http.StatusPaymentRequired, ""); got == "" {
		t.Fatal("expected 402 message")
	}
	if got := summarizeEdgeLicenseStatus(http.StatusForbidden, ""); got == "" {
		t.Fatal("expected 403 message")
	}
	if got := summarizeEdgeLicenseStatus(http.StatusBadGateway, "x"); got != "" {
		t.Fatalf("unexpected message for 502: %q", got)
	}
}

func TestL7StatusErrorUsesLicenseSummary(t *testing.T) {
	err := &l7StatusError{Status: http.StatusLocked, Body: "License config locked"}
	msg := err.Error()
	if msg == "l7 returned status 423: License config locked" {
		t.Fatalf("expected operator-friendly 423 message, got %q", msg)
	}
	if msg == "" {
		t.Fatal("empty error")
	}
}
