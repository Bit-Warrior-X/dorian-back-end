package store

import (
	"strconv"
	"testing"
	"time"
)

func TestBlockLifetimeUsesUnixBlockedAt(t *testing.T) {
	now := time.Unix(1_793_015_979, 0).UTC()
	p := TemporaryBlacklistPayload{
		BlockedAt: strconv.FormatInt(now.Unix(), 10),
		TTL:       180,
	}
	remaining, active := blockLifetime(p, now.Add(30*time.Second))
	if !active {
		t.Fatal("expected active block")
	}
	if remaining < 140*time.Second || remaining > 160*time.Second {
		t.Fatalf("remaining=%v", remaining)
	}
	_, active = blockLifetime(p, now.Add(181*time.Second))
	if active {
		t.Fatal("expected expired block")
	}
}

func TestPayloadToEntryRemainingNeverExceedsTTL(t *testing.T) {
	now := time.Now().UTC()
	p := TemporaryBlacklistPayload{
		IP:        "1.2.3.4",
		BlockedAt: strconv.FormatInt(now.Add(2*time.Minute).Unix(), 10), // future blocked_at
		TTL:       180,
	}
	entry := payloadToEntry(1, p)
	if entry.RemainingSeconds > 180 {
		t.Fatalf("remainingSeconds=%d exceeds TTL", entry.RemainingSeconds)
	}
	if entry.RemainingSeconds <= 0 {
		t.Fatalf("expected positive remaining, got %d", entry.RemainingSeconds)
	}
}

func TestTempIdentity(t *testing.T) {
	a := TemporaryBlacklistPayload{IP: "138.199.196.76", SiteID: 3, URL: "/x"}
	b := TemporaryBlacklistPayload{IP: "138.199.196.76", SiteID: 3, URL: "/x"}
	c := TemporaryBlacklistPayload{IP: "138.199.196.76", SiteID: 3, URL: "/y"}
	if tempIdentity(a) != tempIdentity(b) {
		t.Fatal("expected equal identity")
	}
	if tempIdentity(a) == tempIdentity(c) {
		t.Fatal("expected different identity")
	}
}
