package auth

import (
	"testing"
	"time"
)

func TestOAuthStateRoundTrip(t *testing.T) {
	secret := "test-secret"
	state, err := NewOAuthState("google", "/app/dashboard", true)
	if err != nil {
		t.Fatalf("NewOAuthState: %v", err)
	}
	encoded, err := EncodeOAuthState(state, secret)
	if err != nil {
		t.Fatalf("EncodeOAuthState: %v", err)
	}
	decoded, err := DecodeOAuthState(encoded, secret)
	if err != nil {
		t.Fatalf("DecodeOAuthState: %v", err)
	}
	if decoded.Provider != "google" || !decoded.Remember || decoded.Redirect != "/app/dashboard" {
		t.Fatalf("unexpected decoded state: %+v", decoded)
	}
}

func TestOAuthStateRejectsTampering(t *testing.T) {
	secret := "test-secret"
	state, err := NewOAuthState("google", "/app", false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeOAuthState(state, secret)
	if err != nil {
		t.Fatal(err)
	}
	tampered := encoded + "x"
	if _, err := DecodeOAuthState(tampered, secret); err == nil {
		t.Fatal("expected tamper detection")
	}
}

func TestOAuthStateExpires(t *testing.T) {
	secret := "test-secret"
	state := OAuthState{
		Nonce:    "abc",
		Provider: "google",
		Redirect: "/app",
		IssuedAt: time.Now().Add(-11 * time.Minute).Unix(),
	}
	encoded, err := EncodeOAuthState(state, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeOAuthState(encoded, secret); err != ErrExpiredOAuthState {
		t.Fatalf("expected ErrExpiredOAuthState, got %v", err)
	}
}

func TestSanitizeOAuthRedirect(t *testing.T) {
	if got := sanitizeOAuthRedirect("https://evil.com"); got != "/app" {
		t.Fatalf("external redirect allowed: %q", got)
	}
	if got := sanitizeOAuthRedirect("//evil.com"); got != "/app" {
		t.Fatalf("protocol-relative redirect allowed: %q", got)
	}
	if got := sanitizeOAuthRedirect("/app/sites/list"); got != "/app/sites/list" {
		t.Fatalf("valid redirect rejected: %q", got)
	}
}
