package remotesvc

import (
	"testing"
	"time"
)

func TestParseEdgeHourlyLogListing(t *testing.T) {
	raw := "" +
		"l7\thourly\t22548578304\t2026-10-23T21:00:00\t/usr/local/share/dorian/athens/nginx/logs/access/access-2026-10-23T20.ndjson\n" +
		"l4\thourly\t806976\t2026-10-26T16:52:00\t/usr/local/share/dorian/sparta/logs/sparta-20261026-16.log\n" +
		"l4\tattack\t12000\t2026-10-26T16:40:00\t/usr/local/share/dorian/sparta/logs/attacks/20261026-164000-req_123456789.log\n" +
		"l7\thourly\t1\t2026-10-26T16:00:00\t/etc/passwd\n"
	files := parseEdgeHourlyLogListing(raw)
	if len(files) != 3 {
		t.Fatalf("expected 3 allowlisted files, got %d %#v", len(files), files)
	}
	if files[0].Layer != "l4" || files[0].Name != "sparta-20261026-16.log" {
		t.Fatalf("expected newest first, got %#v", files[0])
	}
	if files[0].Hour != "2026-10-26T16" {
		t.Fatalf("hour label: %q", files[0].Hour)
	}
	if files[2].Hour != "2026-10-23T20" {
		t.Fatalf("athens hour: %q", files[2].Hour)
	}
}

func TestAllowedEdgeLogPath(t *testing.T) {
	ok := []string{
		"/usr/local/share/dorian/athens/nginx/logs/access/access-2026-10-26T16.ndjson",
		"/usr/local/share/dorian/sparta/logs/sparta-20261026-16.log",
		"/usr/local/share/dorian/sparta/logs/latest.log",
		"/usr/local/share/dorian/sparta/logs/attacks/20261026-164000-req_99.log",
	}
	for _, p := range ok {
		if !AllowedEdgeLogPath(p) {
			t.Fatalf("expected allow %s", p)
		}
	}
	deny := []string{
		"/usr/local/share/dorian/athens/nginx/logs/athens_error.log",
		"/usr/local/share/dorian/athens/nginx/logs/access/../athens_error.log",
		"/etc/passwd",
		"/usr/local/share/dorian/sparta/logs/attacks/evil.sh",
	}
	for _, p := range deny {
		if AllowedEdgeLogPath(p) {
			t.Fatalf("expected deny %s", p)
		}
	}
}

func TestParseEdgeHourlyLogPage(t *testing.T) {
	raw := "FILE /usr/local/share/dorian/sparta/logs/sparta-20261026-16.log\nTOTAL 3\nline-a\nline-b\nline-c\n"
	page := parseEdgeHourlyLogPage(raw, 0, 200)
	if page.Total != 3 || len(page.Lines) != 3 || page.HasMore {
		t.Fatalf("%#v", page)
	}
	if page.Name != "sparta-20261026-16.log" {
		t.Fatalf("name %q", page.Name)
	}
}

func TestParseEdgeListingModTime(t *testing.T) {
	got := parseEdgeListingModTime("2026-10-26T16:52:01.1234567890")
	want := time.Date(2026, 10, 26, 16, 52, 1, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %s want %s", got, want)
	}
}
