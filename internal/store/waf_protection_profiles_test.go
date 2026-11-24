package store

import "testing"

func TestProtectionProfileKeyRoundTrip(t *testing.T) {
	cases := []string{
		ProtectionKeyOff,
		ProtectionKeyEssential,
		ProtectionKeyStandard,
		ProtectionKeyStrict,
	}
	for _, key := range cases {
		name := ProtectionProfileName(key)
		if name == "" {
			t.Fatalf("missing name for %s", key)
		}
		if got := ProtectionProfileKeyFromName(name); got != key {
			t.Fatalf("key from name %q: got %q want %q", name, got, key)
		}
	}
	if ProtectionProfileName("nope") != "" {
		t.Fatal("unknown key should map to empty name")
	}
	if ProtectionProfileKeyFromName("Custom pack") != "" {
		t.Fatal("custom names are not profiles")
	}
}
