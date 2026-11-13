package api

import (
	"encoding/json"
	"testing"
)

func TestEdgeMetricsPayloadItemsPreferred(t *testing.T) {
	raw := []byte(`{
		"token": "edge",
		"command": "report_edge_metrics",
		"allows_l4": true,
		"allows_l7": true,
		"items": [
			{"source":"sparta","endpoint":"l4_traffic_stats","timestamp":1,"payload":{"total":1}},
			{"source":"athens","endpoint":"server_traffic_stats","timestamp":1,"payload":{"request_count":2}}
		]
	}`)
	var payload edgeMetricsReportPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) != 2 {
		t.Fatalf("items=%d", len(payload.Items))
	}
	if payload.AllowsL4 == nil || !*payload.AllowsL4 {
		t.Fatal("allows_l4")
	}
	if payload.Items[0].Endpoint != "l4_traffic_stats" {
		t.Fatalf("endpoint=%q", payload.Items[0].Endpoint)
	}
}

func TestEdgeMetricsPayloadSingleItemMirror(t *testing.T) {
	raw := []byte(`{
		"token": "edge",
		"command": "report_edge_metrics",
		"source": "athens",
		"endpoint": "country_request_stats",
		"timestamp": 1742800000,
		"payload": {"timestamp": 1742800000, "country_request_stats": []}
	}`)
	var payload edgeMetricsReportPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Endpoint != "country_request_stats" || payload.Timestamp.Int64() != 1742800000 {
		t.Fatalf("%+v", payload)
	}
}
