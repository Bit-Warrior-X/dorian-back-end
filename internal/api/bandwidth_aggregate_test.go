package api

import (
	"testing"
	"time"

	"vue-project-backend/internal/store"
)

func TestAggregateBandwidthAveragesBuckets(t *testing.T) {
	start := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	at := func(min int) string { return start.Add(time.Duration(min) * time.Minute).Format(time.RFC3339) }
	points := []store.ServerBandwidthPoint{
		{Timestamp: at(0), Bandwidth: 100},
		{Timestamp: at(1), Bandwidth: 300},
		{Timestamp: at(2), Bandwidth: 600},
		{Timestamp: at(5), Bandwidth: 50},
	}
	got := aggregateBandwidth(points, start, 3*time.Minute)
	if len(got) != 2 {
		t.Fatalf("buckets = %d, want 2", len(got))
	}
	if got[0].Bandwidth != 333 || got[0].Peak != 600 || got[0].Timestamp != at(0) {
		t.Fatalf("first bucket = %+v", got[0])
	}
	if got[1].Bandwidth != 50 || got[1].Timestamp != at(3) {
		t.Fatalf("second bucket = %+v", got[1])
	}
}

func TestDashboardBucketSize(t *testing.T) {
	cases := map[time.Duration]time.Duration{
		time.Hour:          time.Minute,
		4 * time.Hour:      time.Minute,
		24 * time.Hour:     4 * time.Minute,
		7 * 24 * time.Hour: 28 * time.Minute,
	}
	for rng, want := range cases {
		if got := dashboardBucketSize(rng); got != want {
			t.Errorf("bucket(%s) = %s, want %s", rng, got, want)
		}
	}
}

func TestCoarsenAnalyticsSeriesCapsLongRanges(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(7 * 24 * time.Hour)
	points := make([]store.TrafficPoint, 0, 7*24*60)
	for i := 0; i < 7*24*60; i++ {
		points = append(points, store.TrafficPoint{
			Timestamp: start.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			Traffic:   100,
		})
	}
	got := coarsenTrafficRate(points, start, end)
	// Truncation can add one edge bucket beyond the nominal max.
	if len(got) > dashboardChartMaxPoints+1 {
		t.Fatalf("points = %d, want ≤ %d", len(got), dashboardChartMaxPoints+1)
	}
	if len(got) < 100 {
		t.Fatalf("points = %d, unexpectedly coarse", len(got))
	}
	short := coarsenTrafficRate(points[:60], start, start.Add(time.Hour))
	if len(short) != 60 {
		t.Fatalf("short range should stay raw, got %d", len(short))
	}
}

func TestAverageBucketsKeepsPerMinuteRates(t *testing.T) {
	start := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	at := func(min int) string { return start.Add(time.Duration(min) * time.Minute).Format(time.RFC3339) }
	points := []store.RequestResponsePoint{
		{Timestamp: at(0), RequestCount: 1},
		{Timestamp: at(1), RequestCount: 0},
		{Timestamp: at(2), RequestCount: 0},
		{Timestamp: at(4), RequestCount: 6, ResponseCount: 3},
	}
	got := averageBuckets(points, start, 3*time.Minute,
		func(p store.RequestResponsePoint) string { return p.Timestamp },
		func(p store.RequestResponsePoint) []int64 { return []int64{p.RequestCount, p.ResponseCount} },
		func(ts string, v []float64) requestResponseRate {
			return requestResponseRate{Timestamp: ts, RequestCount: v[0], ResponseCount: v[1]}
		})
	if len(got) != 2 || got[0].RequestCount != 0.33 || got[1].RequestCount != 6 || got[1].Timestamp != at(3) {
		t.Fatalf("got %+v", got)
	}
}
