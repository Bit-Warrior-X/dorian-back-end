package store

import (
	"testing"
	"time"
)

func TestCoalesceL4CampaignPeriodsFoldsFragments(t *testing.T) {
	serverID := int64(1034)
	base := time.Date(2026, 11, 13, 3, 17, 37, 0, time.UTC)
	mk := func(id string, startOffset, endOffset time.Duration) SecurityEventPeriod {
		start := base.Add(startOffset)
		end := base.Add(endOffset)
		return SecurityEventPeriod{
			ID:        id,
			ReqID:     id,
			ServerID:  &serverID,
			Layer:     "L4",
			Status:    "ended",
			StartedAt: start.Format(time.RFC3339),
			EndedAt:   end.Format(time.RFC3339),
			IPCount:   1,
			Vectors:   []PeriodVector{{Type: "EVENT_TCP_ACK_ATTACK_FIXED_BLOCK", Count: 1}},
		}
	}
	// Five ~10s fragments with ~21s gaps — one continuous ACK flood.
	input := []SecurityEventPeriod{
		mk("5", 132*time.Second, 142*time.Second),
		mk("4", 96*time.Second, 107*time.Second),
		mk("3", 63*time.Second, 73*time.Second),
		mk("2", 31*time.Second, 41*time.Second),
		mk("1", 0, 10*time.Second),
	}
	got := coalesceL4CampaignPeriods(input)
	if len(got) != 1 {
		t.Fatalf("got %d periods, want 1 campaign: %+v", len(got), got)
	}
	if len(got[0].RelatedReqIDs) != 5 {
		t.Fatalf("related=%v", got[0].RelatedReqIDs)
	}
	if got[0].StartedAt != input[4].StartedAt {
		t.Fatalf("started=%s want %s", got[0].StartedAt, input[4].StartedAt)
	}
	if got[0].EndedAt != input[0].EndedAt {
		t.Fatalf("ended=%s want %s", got[0].EndedAt, input[0].EndedAt)
	}
}

func TestCoalesceL4CampaignPeriodsKeepsDistantSeparate(t *testing.T) {
	serverID := int64(1)
	a := SecurityEventPeriod{
		ReqID: "a", ServerID: &serverID, Layer: "L4", Status: "ended",
		StartedAt: "2026-11-13T03:00:00Z", EndedAt: "2026-11-13T03:00:10Z",
	}
	b := SecurityEventPeriod{
		ReqID: "b", ServerID: &serverID, Layer: "L4", Status: "ended",
		StartedAt: "2026-11-13T03:05:00Z", EndedAt: "2026-11-13T03:05:10Z",
	}
	got := coalesceL4CampaignPeriods([]SecurityEventPeriod{b, a})
	if len(got) != 2 {
		t.Fatalf("got %d want 2", len(got))
	}
}
