package store

import "testing"

func TestLatencyHistPercentile(t *testing.T) {
	hist := LatencyHist{10, 20, 30, 20, 10, 5, 3, 1, 0, 0, 1}
	p50 := hist.Percentile(50)
	p95 := hist.Percentile(95)
	p99 := hist.Percentile(99)
	if p50 <= 0 || p50 >= p95 {
		t.Fatalf("expected ordered percentiles, got p50=%v p95=%v", p50, p95)
	}
	if p95 >= p99 && p99 == 0 {
		t.Fatalf("unexpected p99=%v", p99)
	}
	if MergeLatencyHists([]LatencyHist{hist, hist}).Sum() != hist.Sum()*2 {
		t.Fatalf("merge sum mismatch")
	}
}
