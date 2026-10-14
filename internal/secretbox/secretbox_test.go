package secretbox

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func testBox(t *testing.T, fill byte) *Box {
	t.Helper()
	box, err := New(bytes.Repeat([]byte{fill}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func TestSealOpenRoundTrip(t *testing.T) {
	box := testBox(t, 7)
	for _, plain := range []string{"hunter2", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n", "ünïcode"} {
		sealed, err := box.Seal(plain)
		if err != nil {
			t.Fatal(err)
		}
		if !IsSealed(sealed) || strings.Contains(sealed, plain) {
			t.Fatalf("sealed value leaks plaintext: %q", sealed)
		}
		again, _ := box.Seal(plain)
		if again == sealed {
			t.Fatal("expected a fresh nonce per Seal")
		}
		opened, err := box.Open(sealed)
		if err != nil || opened != plain {
			t.Fatalf("Open = %q, %v; want %q", opened, err, plain)
		}
	}
}

func TestEmptyAndLegacyPassThrough(t *testing.T) {
	box := testBox(t, 1)
	if s, _ := box.Seal(""); s != "" {
		t.Fatalf("Seal(\"\") = %q", s)
	}
	if s, _ := box.Open("legacy-plain"); s != "legacy-plain" {
		t.Fatalf("Open(legacy) = %q", s)
	}
	sealed, _ := box.Seal("x")
	if twice, _ := box.Seal(sealed); twice != sealed {
		t.Fatal("Seal must not double-encrypt")
	}
}

func TestWrongKeyAndTamperFail(t *testing.T) {
	sealed, _ := testBox(t, 1).Seal("secret")
	if _, err := testBox(t, 2).Open(sealed); err == nil {
		t.Fatal("expected failure with wrong key")
	}
	tampered := sealed[:len(sealed)-2] + "AA"
	if _, err := testBox(t, 1).Open(tampered); err == nil {
		t.Fatal("expected failure on tampered ciphertext")
	}
}

func TestParseKey(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, KeySize)
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString(key),
		base64.RawURLEncoding.EncodeToString(key),
		hex.EncodeToString(key),
	} {
		got, err := ParseKey(enc)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("ParseKey(%q) = %x, %v", enc, got, err)
		}
	}
	if _, err := ParseKey("short"); err == nil {
		t.Fatal("expected error for short key")
	}
	if _, err := ParseKey(""); err == nil {
		t.Fatal("expected error for empty key")
	}
}
