package auth_test

import (
	"testing"
	"time"

	"vue-project-backend/internal/auth"
)

func TestIssueAndParseUserToken(t *testing.T) {
	secret := "test-secret-value-1234567890"
	token, err := auth.IssueUserToken(auth.UserIdentity{
		ID:    42,
		Email: "admin@example.com",
		Name:  "Admin",
		Role:  "Admin",
	}, secret, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if token == "" || token == "mock-token" {
		t.Fatalf("unexpected token %q", token)
	}

	claims, err := auth.ParseUserToken(token, secret)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.UserID != 42 || claims.Email != "admin@example.com" || claims.Role != "Admin" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestParseUserTokenRejectsBadSecret(t *testing.T) {
	token, err := auth.IssueUserToken(auth.UserIdentity{ID: 1, Email: "a@b.c", Role: "User"}, "good-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ParseUserToken(token, "wrong-secret"); err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestParseUserTokenRejectsExpired(t *testing.T) {
	token, err := auth.IssueUserToken(auth.UserIdentity{ID: 1, Email: "a@b.c", Role: "User"}, "good-secret", time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := auth.ParseUserToken(token, "good-secret"); err == nil {
		t.Fatal("expected expired error")
	}
}
