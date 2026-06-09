package remotesvc

import "testing"

func TestNormalizeHostOS(t *testing.T) {
	tests := map[string]string{
		"ubuntu-22.04":  "ubuntu-22.04",
		" Ubuntu-24.04 ": "ubuntu-24.04",
		"":              "",
	}
	for input, want := range tests {
		if got := NormalizeHostOS(input); got != want {
			t.Fatalf("NormalizeHostOS(%q) = %q, want %q", input, got, want)
		}
	}
}
