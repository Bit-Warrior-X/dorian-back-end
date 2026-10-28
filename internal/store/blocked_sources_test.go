package store

import (
	"strings"
	"testing"
)

func TestSanitizeSourceMatch(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":            "1.2.3.4",
		"  10.1.2 ":          "10.1.2",
		"2001:db8::1":        "2001:db8::1",
		"1.2.3%; DROP TABLE": "1.2.3DABE",
		"":                   "",
	}
	for in, want := range cases {
		if got := sanitizeSourceMatch(in); got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
	if got := sanitizeSourceMatch(strings.Repeat("1", 80)); len(got) != 64 {
		t.Fatalf("len=%d want 64", len(got))
	}
}
