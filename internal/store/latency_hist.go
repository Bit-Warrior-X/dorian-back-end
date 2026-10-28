package store

import (
	"encoding/json"
	"math"
)

// Athens latency histogram upper bounds (ms); last bucket is +Inf.
var latencyBoundsMs = [...]float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, math.Inf(1)}

const latencyHistBuckets = 11

// LatencyHist is the fixed 11-bucket Athens latency histogram.
type LatencyHist [latencyHistBuckets]int64

func ParseLatencyHist(raw []float64) LatencyHist {
	var out LatencyHist
	n := len(raw)
	if n > latencyHistBuckets {
		n = latencyHistBuckets
	}
	for i := 0; i < n; i++ {
		v := raw[i]
		if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		out[i] = int64(math.Round(v))
	}
	return out
}

func (h LatencyHist) MarshalJSON() ([]byte, error) {
	vals := make([]int64, latencyHistBuckets)
	copy(vals, h[:])
	return json.Marshal(vals)
}

func (h *LatencyHist) UnmarshalJSON(data []byte) error {
	var vals []float64
	if err := json.Unmarshal(data, &vals); err != nil {
		return err
	}
	*h = ParseLatencyHist(vals)
	return nil
}

func (h LatencyHist) Sum() int64 {
	var total int64
	for _, v := range h {
		total += v
	}
	return total
}

func (h *LatencyHist) Add(other LatencyHist) {
	for i := range h {
		h[i] += other[i]
	}
}

func MergeLatencyHists(items []LatencyHist) LatencyHist {
	var out LatencyHist
	for _, item := range items {
		out.Add(item)
	}
	return out
}

// Percentile estimates the given percentile (0–100) from a non-cumulative histogram.
func (h LatencyHist) Percentile(p float64) float64 {
	total := h.Sum()
	if total <= 0 {
		return 0
	}
	if p <= 0 {
		return 0
	}
	if p >= 100 {
		p = 100
	}
	target := (p / 100) * float64(total)
	var cumulative int64
	lower := 0.0
	for i, count := range h {
		next := cumulative + count
		upper := latencyBoundsMs[i]
		if float64(next) >= target {
			if count <= 0 {
				if math.IsInf(upper, 1) {
					return lower * 1.5
				}
				return upper
			}
			frac := (target - float64(cumulative)) / float64(count)
			if math.IsInf(upper, 1) {
				// Place Inf bucket samples just above the previous bound.
				span := lower
				if span <= 0 {
					span = 10000
				}
				return lower + frac*span
			}
			return lower + frac*(upper-lower)
		}
		cumulative = next
		if !math.IsInf(upper, 1) {
			lower = upper
		}
	}
	return lower
}

func round1f(v float64) float64 {
	return math.Round(v*10) / 10
}
