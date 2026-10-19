package api

import (
	"testing"
	"time"

	"vue-project-backend/internal/remotesvc"
)

func TestAlignEdgeLocalTime(t *testing.T) {
	now := time.Date(2026, 10, 15, 14, 24, 40, 0, time.UTC)
	cases := []struct {
		name string
		wall time.Time
		want time.Time
	}{
		{"utc+2 edge", time.Date(2026, 10, 15, 16, 24, 39, 0, time.UTC), time.Date(2026, 10, 15, 14, 24, 39, 0, time.UTC)},
		{"utc edge", time.Date(2026, 10, 15, 14, 24, 39, 0, time.UTC), time.Date(2026, 10, 15, 14, 24, 39, 0, time.UTC)},
		{"utc-5 edge", time.Date(2026, 10, 15, 9, 24, 30, 0, time.UTC), time.Date(2026, 10, 15, 14, 24, 30, 0, time.UTC)},
		{"utc+5:30 edge", time.Date(2026, 10, 15, 19, 54, 41, 0, time.UTC), time.Date(2026, 10, 15, 14, 24, 41, 0, time.UTC)},
		{"far from now", time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC), time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		if got := alignEdgeLocalTime(tc.wall, now); !got.Equal(tc.want) {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestAttackTypeLabelMatchesWholeWords(t *testing.T) {
	cases := map[string]string{
		"EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK": "HANDSHAKE",
		"EVENT_UDP_ATTACK_BURST_BLOCK":           "UDP",
		"EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK":     "STOMP",
		"EVENT_TCP_ACK_ATTACK_FIXED_BLOCK":       "TCP ACK",
		"EVENT_ICMP_ATTACK_FIXED_BLOCK":          "ICMP",
	}
	for raw, want := range cases {
		if got := attackTypeLabel(raw); got != want {
			t.Errorf("%s: got %q, want %q", raw, got, want)
		}
	}
}

func TestToAttackLogLinesUsesSpartaStamp(t *testing.T) {
	journal := time.Date(2026, 10, 15, 14, 19, 55, 0, time.UTC)
	start := time.Date(2026, 10, 15, 14, 19, 39, 0, time.UTC)
	end := start.Add(10 * time.Minute)
	lines := toAttackLogLines([]remotesvc.JournalLine{
		{Time: journal, Message: "[2026-10-15 16:19:40]   SYN:    2/2     ACK:    2/0"},
		{Time: journal, Message: "[2026-10-15 16:19:30]   SYN:    0/0"},
	}, start, end)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	if lines[0].Time != "2026-10-15T14:19:40Z" || lines[0].Text != "SYN:    2/2     ACK:    2/0" {
		t.Errorf("got %+v", lines[0])
	}
}

func TestParseReportEventTimeKeepsZonedValues(t *testing.T) {
	got, err := parseReportEventTime("2026-10-15T16:24:39+02:00")
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 10, 15, 14, 24, 39, 0, time.UTC); !got.Equal(want) {
		t.Errorf("got %s, want %s", got, want)
	}
}
