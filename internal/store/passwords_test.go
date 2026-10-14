package store

import (
	"strings"
	"testing"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !isBcryptHash(hash) {
		t.Fatalf("expected bcrypt hash, got %q", hash)
	}
	if !passwordMatches(hash, "correct horse") {
		t.Fatal("expected password to match its hash")
	}
	if passwordMatches(hash, "wrong") {
		t.Fatal("expected wrong password to be rejected")
	}
}

func TestHashPasswordTooLong(t *testing.T) {
	_, err := HashPassword(strings.Repeat("a", MaxPasswordBytes+1))
	if !IsPasswordTooLong(err) {
		t.Fatalf("expected ErrPasswordTooLong, got %v", err)
	}
}

func TestPasswordMatchesLegacyPlaintext(t *testing.T) {
	if !passwordMatches("123456", "123456") {
		t.Fatal("expected legacy plaintext to match until migrated")
	}
	if passwordMatches("123456", "1234567") {
		t.Fatal("expected mismatched legacy plaintext to be rejected")
	}
}

func TestPasswordMatchesEmpty(t *testing.T) {
	if passwordMatches("", "") {
		t.Fatal("empty stored password must never match")
	}
	hash, _ := HashPassword("x")
	if passwordMatches(hash, "") {
		t.Fatal("empty candidate must never match")
	}
}
