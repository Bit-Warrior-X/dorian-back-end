package api

import "testing"

func TestDownsampleDropSeriesKeepsEnds(t *testing.T) {
	drops := make([]attackDropPoint, 1000)
	for i := range drops {
		drops[i] = attackDropPoint{Timestamp: string(rune('a' + (i % 26))), Blocked: int64(i)}
	}
	got := downsampleDropSeries(drops, 480)
	if len(got) != 480 {
		t.Fatalf("len=%d want 480", len(got))
	}
	if got[0].Blocked != 0 || got[len(got)-1].Blocked != 999 {
		t.Fatalf("ends: first=%d last=%d", got[0].Blocked, got[len(got)-1].Blocked)
	}
	if len(downsampleDropSeries(drops[:10], 480)) != 10 {
		t.Fatalf("short series should pass through")
	}
}

func TestOverlayAttackTypeWindows(t *testing.T) {
	types := []attackTypeCount{{Type: "SYN", Count: 500}}
	from := []attackTypeCount{{Type: "SYN", Count: 12, StartedAt: "a", EndedAt: "b"}}
	got := overlayAttackTypeWindows(types, from)
	if got[0].Count != 500 || got[0].StartedAt != "a" || got[0].EndedAt != "b" {
		t.Fatalf("got %+v", got[0])
	}
	if empty := overlayAttackTypeWindows(nil, from); len(empty) != 1 || empty[0].Count != 12 {
		t.Fatalf("empty types should use blocks: %+v", empty)
	}
}
