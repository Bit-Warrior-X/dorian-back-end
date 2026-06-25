package store

import "testing"

func TestNormalizeUpstreamAddress(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"192.168.1.10:8080", "192.168.1.10:8080"},
		{" 192.168.1.10:080 ", "192.168.1.10:80"},
		{"Example.COM:443", "example.com:443"},
		{"[2001:db8::1]:443", "2001:db8::1:443"},
	}
	for _, tc := range tests {
		if got := NormalizeUpstreamAddress(tc.in); got != tc.want {
			t.Fatalf("NormalizeUpstreamAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUpstreamAddressExists(t *testing.T) {
	list := []UpstreamServer{
		{ID: 1, Address: "10.0.0.1:80"},
		{ID: 2, Address: "10.0.0.2:8080"},
	}
	if !UpstreamAddressExists(list, "10.0.0.1:080", 0) {
		t.Fatal("expected duplicate detection for normalized port")
	}
	if UpstreamAddressExists(list, "10.0.0.1:80", 1) {
		t.Fatal("expected same row to be excluded")
	}
	if UpstreamAddressExists(list, "10.0.0.3:80", 0) {
		t.Fatal("expected unique address")
	}
}
