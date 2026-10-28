package remotesvc

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeSpartaReqID(t *testing.T) {
	cases := map[string]string{
		"1879754096508929":        "1879754096508929",
		"req_1879754096508929":    "1879754096508929",
		"REQ_1879754096508929":    "1879754096508929",
		"  req_1879754096508929 ": "1879754096508929",
	}
	for in, want := range cases {
		got, err := NormalizeSpartaReqID(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "req_", "abc", "req_abc", "../etc/passwd"} {
		if _, err := NormalizeSpartaReqID(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestParseSpartaAttackArchive(t *testing.T) {
	raw := `ARCHIVE_FILE /usr/local/share/dorian/sparta/logs/attacks/20261022-144643-req_1879754096508929.log
ARCHIVE_STARTED 2026-10-22 14:46:43
[2026-10-22 14:46:43]   SYN:    0/0     ACK:    4/4
[2026-10-22 14:46:44]   SYN:    0/0     ACK:    1/1
`
	archive := parseSpartaAttackArchive(raw)
	if len(archive.Lines) != 2 {
		t.Fatalf("got %d lines", len(archive.Lines))
	}
	wantStart := time.Date(2026, 10, 22, 14, 46, 43, 0, time.UTC)
	if !archive.EdgeStart.Equal(wantStart) {
		t.Fatalf("EdgeStart=%v want %v", archive.EdgeStart, wantStart)
	}
	if archive.Lines[0].Time.Year() > 1 {
		t.Fatalf("archive line Time should be zero, got %v", archive.Lines[0].Time)
	}
	if !strings.Contains(archive.Lines[0].Message, "SYN:") {
		t.Fatalf("unexpected message: %q", archive.Lines[0].Message)
	}
}

func TestParseSpartaAttackArchiveFallsBackToFilename(t *testing.T) {
	raw := `ARCHIVE_FILE /usr/local/share/dorian/sparta/logs/attacks/20261022-144643-req_1879754096508929.log
ARCHIVE_STARTED 
[2026-10-22 14:46:43]   SYN:    0/0
`
	archive := parseSpartaAttackArchive(raw)
	wantStart := time.Date(2026, 10, 22, 14, 46, 43, 0, time.UTC)
	if !archive.EdgeStart.Equal(wantStart) {
		t.Fatalf("EdgeStart=%v want %v", archive.EdgeStart, wantStart)
	}
}

func TestParseSpartaAttackArchivePage(t *testing.T) {
	raw := `ARCHIVE_FILE /usr/local/share/dorian/sparta/logs/attacks/20261022-144643-req_1879754096508929.log
ARCHIVE_STARTED 2026-10-22 14:46:43
ARCHIVE_TOTAL 8345
# header
[2026-10-22 14:46:43]   CRITIC  DETECT FIN flood protection START
[2026-10-22 14:46:43]   SYN:    0/0     ACK:    4/4
`
	page := parseSpartaAttackArchivePage(raw, 0, 200)
	if page.Total != 8345 || !page.HasMore {
		t.Fatalf("total/hasMore: %+v", page)
	}
	if page.File == "" || !strings.Contains(page.File, "req_1879754096508929") {
		t.Fatalf("file: %q", page.File)
	}
	if len(page.Lines) < 3 {
		t.Fatalf("lines=%d want >= 3", len(page.Lines))
	}
	if page.Lines[0].Message != "# header" {
		t.Fatalf("keep comments: %q", page.Lines[0].Message)
	}
	if page.Lines[1].Time.IsZero() {
		t.Fatalf("stamped line should carry wall time")
	}
	if !strings.Contains(page.Lines[2].Message, "SYN:") {
		t.Fatalf("counter line: %q", page.Lines[2].Message)
	}
}

func TestParseSpartaAttackArchivePageCounters(t *testing.T) {
	raw := `ARCHIVE_FILE /usr/local/share/dorian/sparta/logs/attacks/20261022-144643-req_1879754096508929.log
ARCHIVE_STARTED 2026-10-22 14:46:43
ARCHIVE_TOTAL 0
[2026-10-22 14:46:43]   SYN:    0/0     ACK:    4/4
[2026-10-22 14:46:44]   SYN:    0/0     ACK:    1/1
`
	page := parseSpartaAttackArchivePage(raw, 0, 80)
	if page.File == "" || page.Total != 0 {
		t.Fatalf("file/total: %+v", page)
	}
	if len(page.Lines) != 2 {
		t.Fatalf("lines=%d want 2", len(page.Lines))
	}
	if page.HasMore {
		t.Fatalf("short first page should not claim more")
	}

	var full strings.Builder
	full.WriteString("ARCHIVE_FILE /tmp/x.log\nARCHIVE_STARTED 2026-10-22 14:46:43\nARCHIVE_TOTAL 0\n")
	for i := 0; i < 80; i++ {
		full.WriteString("[2026-10-22 14:46:43]   SYN:    1/0\n")
	}
	next := parseSpartaAttackArchivePage(full.String(), 0, 80)
	if !next.HasMore || len(next.Lines) != 80 {
		t.Fatalf("full page without total should have more: %+v lines=%d", next, len(next.Lines))
	}
}

func TestParseSpartaAttackArchivePageHasMoreMeta(t *testing.T) {
	raw := `ARCHIVE_FILE /tmp/x.log
ARCHIVE_STARTED 2026-10-22 14:46:43
ARCHIVE_TOTAL 0
ARCHIVE_HAS_MORE 1
[2026-10-22 14:46:43]   SYN:    1/0
`
	page := parseSpartaAttackArchivePage(raw, 0, 80)
	if !page.HasMore {
		t.Fatalf("ARCHIVE_HAS_MORE should win: %+v", page)
	}
	done := parseSpartaAttackArchivePage(strings.Replace(raw, "ARCHIVE_HAS_MORE 1", "ARCHIVE_HAS_MORE 0", 1), 80, 80)
	if done.HasMore {
		t.Fatalf("ARCHIVE_HAS_MORE 0 should clear more: %+v", done)
	}
}
