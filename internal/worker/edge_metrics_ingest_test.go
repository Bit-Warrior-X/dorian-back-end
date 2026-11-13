package worker

import (
	"encoding/json"
	"testing"
)

func TestDecodeL4AttackBucketPrefersNestedStats(t *testing.T) {
	raw := []byte(`{
		"timestamp": 1742800000,
		"stats": {"total": 10, "allow": 8, "block": 2, "tcp": 9, "udp": 1, "syn": 3, "ack": 5, "rst": 1},
		"total": 999,
		"allow": 999
	}`)
	got, err := decodeL4AttackBucket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stats.Total != 10 || got.Stats.Allow != 8 || got.Stats.Block != 2 {
		t.Fatalf("stats=%+v", got.Stats)
	}
}

func TestDecodeL4AttackBucketFallsBackToFlat(t *testing.T) {
	raw := []byte(`{
		"timestamp": 1742800000,
		"total": 1500,
		"allow": 1400,
		"block": 100,
		"tcp": 1400,
		"udp": 90,
		"icmp": 5,
		"gre": 2,
		"other": 3,
		"syn": 400,
		"ack": 900,
		"rst": 12
	}`)
	got, err := decodeL4AttackBucket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stats.Total != 1500 || got.Stats.Block != 100 || got.Stats.UDP != 90 {
		t.Fatalf("stats=%+v", got.Stats)
	}
}

func TestAverageL4StatsOverInterval(t *testing.T) {
	stats := l4AttackStatsInner{
		Total: 1368662010,
		Allow: 1368506270,
		Block: 155740,
		Ack:   1317036650,
		TCP:   1360000000,
	}
	averageL4StatsOverInterval(&stats, 60)
	if stats.Total != 22811033 || stats.Block != 2595 || stats.Ack != 21950610 {
		t.Fatalf("averaged=%+v", stats)
	}
	averageL4StatsOverInterval(&stats, 1) // no-op
	if stats.Total != 22811033 {
		t.Fatalf("interval=1 changed stats: %d", stats.Total)
	}
}

func TestNormalizeMetricsEndpoint(t *testing.T) {
	if got := normalizeMetricsEndpoint("l4_traffic_stats", nil); got != "l4_traffic_stats" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeMetricsEndpoint("", []string{"l4_attack_stats"}); got != "l4_attack_stats" {
		t.Fatalf("got %q", got)
	}
}

func TestEdgeMetricsItemJSON(t *testing.T) {
	raw := []byte(`{
		"source": "athens",
		"endpoint": "ip_request_stats",
		"timestamp": 1742800000,
		"payload": {"timestamp": 1742800000, "ip_request_stats": [{"site_id": 1, "ip": "1.2.3.4", "request_count": 9}]}
	}`)
	var item EdgeMetricsItem
	if err := json.Unmarshal(raw, &item); err != nil {
		t.Fatal(err)
	}
	if item.Endpoint != "ip_request_stats" || item.Timestamp != 1742800000 || len(item.Payload) == 0 {
		t.Fatalf("%+v", item)
	}
}
