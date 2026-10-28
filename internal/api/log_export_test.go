package api

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseLogExportWindow(t *testing.T) {
	start, end, err := parseLogExportWindow("2026-10-25", "2026-10-25")
	if err != nil {
		t.Fatal(err)
	}
	if end.Sub(start) != 24*time.Hour {
		t.Fatalf("expected 1 day exclusive window, got %s", end.Sub(start))
	}
	if _, _, err := parseLogExportWindow("2026-10-26", "2026-10-25"); err == nil {
		t.Fatal("expected start>end error")
	}

	start, end, err = parseLogExportWindow("2026-10-25 14:00", "2026-10-25 15:00")
	if err != nil {
		t.Fatal(err)
	}
	if end.Sub(start) != time.Hour+time.Minute {
		t.Fatalf("datetime window should include end minute, got %s", end.Sub(start))
	}

	// Frontend Today/presets send Date.toISOString() values.
	start, end, err = parseLogExportWindow("2026-10-26T00:00:00.000Z", "2026-10-26T15:30:45.123Z")
	if err != nil {
		t.Fatal(err)
	}
	if !start.Equal(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("iso start: %s", start)
	}
	if end.Sub(start) <= 15*time.Hour {
		t.Fatalf("iso end should include picked minute, got %s", end.Sub(start))
	}
}

func TestSerializeLogExportCSV(t *testing.T) {
	rows := []logExportRow{{
		Time: "2026-10-25T15:18:47.013Z", ClientIP: "1.2.3.4", Method: "GET",
		Host: "xstream.wtf", Path: "/a", Status: 200, Bytes: 10, LogKind: "access",
		ServerName: "edge-20", Action: "allow",
	}}
	body, err := serializeLogExport(rows, "csv")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "clientIp") || !strings.Contains(text, "1.2.3.4") {
		t.Fatalf("csv: %s", text)
	}
}

func TestSerializeLogExportJSONEmpty(t *testing.T) {
	body, err := serializeLogExport(nil, "json")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "[]" && !strings.Contains(string(body), "[]") {
		t.Fatalf("got %s", body)
	}
}

func TestAnalyticsExportPathAllowsReadScope(t *testing.T) {
	if !apiTokenAllows([]string{"analytics:read"}, http.MethodPost, "/analytics/logs/export") {
		t.Fatal("analytics:read should allow export POST")
	}
	if apiTokenAllows([]string{"analytics:read"}, http.MethodPost, "/analytics/summary") {
		t.Fatal("analytics:read must not allow arbitrary POST")
	}
}
