package api

import (
	"testing"
	"time"

	"vue-project-backend/internal/remotesvc"
	"vue-project-backend/internal/store"
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
		"EVENT_TCP_HANDSHAKE_ATTACK_FIXED_BLOCK":    "HANDSHAKE",
		"EVENT_UDP_ATTACK_BURST_BLOCK":              "UDP",
		"EVENT_TCP_STOMP_ATTACK_FIXED_BLOCK":        "STOMP",
		"EVENT_TCP_ACK_ATTACK_FIXED_BLOCK":          "TCP ACK",
		"EVENT_TCP_RST_ATTACK_PROTECION_MODE_START": "TCP RST",
		"EVENT_ICMP_ATTACK_FIXED_BLOCK":             "ICMP",
	}
	for raw, want := range cases {
		if got := attackTypeLabel(raw); got != want {
			t.Errorf("%s: got %q, want %q", raw, got, want)
		}
	}
}

func TestMergeAttackTypesWithProtection(t *testing.T) {
	period := store.SecurityEventPeriod{
		Events: []store.SecurityEvent{
			{Command: "report_protection", Data: "EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START", CreatedAt: "2026-10-22T14:38:16Z"},
			{Command: "report_protection", Data: "EVENT_TCP_RST_ATTACK_PROTECION_MODE_START", CreatedAt: "2026-10-22T14:39:50Z"},
			{Command: "report_protection", Data: "EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END", CreatedAt: "2026-10-22T14:41:51Z"},
			{Command: "report_protection", Data: "EVENT_TCP_RST_ATTACK_PROTECION_MODE_END", CreatedAt: "2026-10-22T14:45:18Z"},
		},
	}
	got := mergeAttackTypesWithProtection([]attackTypeCount{{Type: "TCP ACK", Count: 318, StartedAt: "2026-10-22T14:38:17Z", EndedAt: "2026-10-22T14:39:15Z"}}, period)
	if len(got) != 2 {
		t.Fatalf("got %d types, want 2: %#v", len(got), got)
	}
	if got[0].Type != "TCP ACK" || got[0].Count != 318 || got[0].StartedAt != "2026-10-22T14:38:16Z" || got[0].EndedAt != "2026-10-22T14:41:51Z" {
		t.Fatalf("ACK vector: %#v", got[0])
	}
	if got[1].Type != "TCP RST" || got[1].Count != 0 || got[1].StartedAt != "2026-10-22T14:39:50Z" || got[1].EndedAt != "2026-10-22T14:45:18Z" {
		t.Fatalf("RST vector: %#v", got[1])
	}
	if title := multiVectorTitle(got); title != "TCP ACK + TCP RST flood" {
		t.Fatalf("title: %q", title)
	}
}

func TestToAttackLogLinesUsesSpartaStamp(t *testing.T) {
	journal := time.Date(2026, 10, 15, 14, 19, 55, 0, time.UTC)
	start := time.Date(2026, 10, 15, 14, 19, 39, 0, time.UTC)
	end := start.Add(10 * time.Minute)
	lines := toAttackLogLines([]remotesvc.JournalLine{
		{Time: journal, Message: "[2026-10-15 16:19:40]   SYN:    2/2     ACK:    2/0"},
		{Time: journal, Message: "[2026-10-15 16:19:30]   SYN:    0/0"},
	}, start, end, time.Time{})
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	if lines[0].Time != "2026-10-15T14:19:40Z" || lines[0].Text != "SYN:    2/2     ACK:    2/0" {
		t.Errorf("got %+v", lines[0])
	}
}

func TestToAttackLogLinesAlignsHistoricalArchive(t *testing.T) {
	// Edge wall-clock is UTC+2; DB attack window is UTC. Archive lines have no journal epoch.
	start := time.Date(2026, 10, 22, 12, 41, 43, 0, time.UTC) // padded period start
	end := time.Date(2026, 10, 22, 13, 17, 18, 0, time.UTC)
	edgeStart := time.Date(2026, 10, 22, 14, 46, 43, 0, time.UTC) // from # started / filename
	lines := toAttackLogLines([]remotesvc.JournalLine{
		{Message: "[2026-10-22 14:46:43]   SYN:    0/0     ACK:    4/4"},
		{Message: "[2026-10-22 14:46:44]   SYN:    0/0     ACK:    1/1"},
		{Message: "[2026-10-22 16:00:00]   SYN:    9/9"}, // outside padded window
	}, start, end, edgeStart)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %+v", len(lines), lines)
	}
	if lines[0].Time != "2026-10-22T12:46:43Z" || lines[1].Time != "2026-10-22T12:46:44Z" {
		t.Fatalf("times: %q %q", lines[0].Time, lines[1].Time)
	}
	if lines[0].Text != "SYN:    0/0     ACK:    4/4" {
		t.Fatalf("text: %q", lines[0].Text)
	}
}

func TestToAttackLogLinesKeepsArchiveWhenStampWasCopiedOntoTime(t *testing.T) {
	// The pager stores the wall-clock stamp in Time. That must not be treated
	// as a UTC journal epoch, or every counter falls outside the attack window.
	start := time.Date(2026, 10, 22, 12, 41, 43, 0, time.UTC)
	end := time.Date(2026, 10, 22, 13, 17, 18, 0, time.UTC)
	edgeStart := time.Date(2026, 10, 22, 14, 46, 43, 0, time.UTC)
	wall := time.Date(2026, 10, 22, 14, 46, 44, 0, time.UTC)
	lines := toAttackLogLines([]remotesvc.JournalLine{
		{Time: wall, Message: "[2026-10-22 14:46:44]   SYN:    0/0     ACK:    1/1"},
	}, start, end, edgeStart)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %+v", len(lines), lines)
	}
	if lines[0].Time != "2026-10-22T12:46:44Z" {
		t.Fatalf("time: %s", lines[0].Time)
	}
}

func TestFilterCounterArchiveLines(t *testing.T) {
	lines := []attackLogLine{
		{Text: "# started: 2026-10-22 14:46:43"},
		{Text: "CRITIC  DETECT FIN flood protection START"},
		{Text: "SYN:    0/0     ACK:    4/4"},
		{Text: "HANDSHAKE: 3/1"},
	}
	got := filterCounterArchiveLines(lines)
	if len(got) != 2 {
		t.Fatalf("got %d lines, want 2: %+v", len(got), got)
	}
	if got[0].Text != "SYN:    0/0     ACK:    4/4" || got[1].Text != "HANDSHAKE: 3/1" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestConvertAttackLogLinesKeepsTailOutsideWindow(t *testing.T) {
	start := time.Date(2026, 10, 22, 12, 41, 43, 0, time.UTC)
	end := time.Date(2026, 10, 22, 13, 17, 18, 0, time.UTC)
	edgeStart := time.Date(2026, 10, 22, 14, 46, 43, 0, time.UTC)
	raw := []remotesvc.JournalLine{
		{Message: "[2026-10-22 16:00:00]   SYN:    9/9"},
	}
	if got := toAttackLogLines(raw, start, end, edgeStart); len(got) != 0 {
		t.Fatalf("window filter should drop the tail, got %+v", got)
	}
	kept := convertAttackLogLines(raw, start, end, edgeStart, false)
	if len(kept) != 1 || kept[0].Text != "SYN:    9/9" {
		t.Fatalf("unfiltered archive tail: %+v", kept)
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
