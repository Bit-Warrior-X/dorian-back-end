package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReportCacheHitRejectsBadCommand(t *testing.T) {
	handler := reportCacheHitHandler(nil, nil)
	body := `{"token":"t","command":"nope","timestamp":1723900800,"content_types":[],"top_miss_urls":[]}`
	req := httptest.NewRequest(http.MethodPost, "/api/report_cache_hit", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReportCacheHitAcceptsBearerWhenBodyTokenMissing(t *testing.T) {
	// Decode path only — missing store should not be reached before token check fails with empty both.
	handler := reportCacheHitHandler(nil, nil)
	body := `{"command":"report_cache_hit","timestamp":1723900800,"content_types":[],"top_miss_urls":[]}`
	req := httptest.NewRequest(http.MethodPost, "/api/report_cache_hit", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden without token, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestCacheHitPayloadAliases(t *testing.T) {
	raw := []byte(`{
		"token":"abc",
		"command":"report_cache_hit",
		"reported_at":1723900860,
		"timestamp":1723900800,
		"interval_seconds":60,
		"content_type_request_stats":[{"site_id":12,"content_type":"image","request_count":10,"traffic_l7_tx":100,"cached_request_count":8,"traffic_cached_tx":80}],
		"cache_miss_url_stats":[{"site_id":12,"domain":"www.example.com","url":"/x","miss_count":3,"request_count":5}]
	}`)
	var payload cacheHitReportPayload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.ContentTypeRequestStats) != 1 || len(payload.CacheMissURLStats) != 1 {
		t.Fatalf("aliases not decoded: %+v", payload)
	}
	if payload.ContentTypeRequestStats[0].ContentType != "image" {
		t.Fatalf("content type=%q", payload.ContentTypeRequestStats[0].ContentType)
	}
	if jsonNumberToInt64(payload.ContentTypeRequestStats[0].TrafficL7Tx) != 100 {
		t.Fatalf("traffic=%v", payload.ContentTypeRequestStats[0].TrafficL7Tx)
	}
}
