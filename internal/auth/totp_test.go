package auth

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors (SHA1, 8 digits) truncated to 6 digits.
func TestTOTPCodeRFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, tc := range cases {
		if got := totpCode(key, tc.unix/totpPeriod); got != tc.want {
			t.Errorf("unix=%d: got %s want %s", tc.unix, got, tc.want)
		}
	}
}

func TestValidateTOTP(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	now := time.Unix(1111111111, 0)

	step, ok := ValidateTOTP(secret, "050471", now, 0)
	if !ok || step != 1111111111/totpPeriod {
		t.Fatalf("expected valid code, got ok=%v step=%d", ok, step)
	}
	if _, ok := ValidateTOTP(secret, "050471", now, step); ok {
		t.Fatal("expected replayed code to be rejected")
	}
	if _, ok := ValidateTOTP(secret, "050471", now.Add(31*time.Second), 0); !ok {
		t.Fatal("expected previous-step code to be accepted within skew")
	}
	if _, ok := ValidateTOTP(secret, "050471", now.Add(5*time.Minute), 0); ok {
		t.Fatal("expected stale code to be rejected")
	}
	if _, ok := ValidateTOTP(secret, "000000", now, 0); ok {
		t.Fatal("expected wrong code to be rejected")
	}
	if _, ok := ValidateTOTP(secret, "12345", now, 0); ok {
		t.Fatal("expected short code to be rejected")
	}
}

func TestGenerateTOTPSecret(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Fatalf("expected 32-char base32 secret, got %d", len(secret))
	}
}

func TestMFAChallengeTokenIsNotASessionToken(t *testing.T) {
	token, err := IssueMFAChallengeToken(42, "jwt-secret", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseUserToken(token, "jwt-secret"); err == nil {
		t.Fatal("challenge token must not be accepted as a session token")
	}
	userID, err := ParseMFAChallengeToken(token, "jwt-secret")
	if err != nil || userID != 42 {
		t.Fatalf("expected user 42, got %d err=%v", userID, err)
	}

	session, _ := IssueUserToken(UserIdentity{ID: 42, Email: "a@b.c"}, "jwt-secret", time.Minute)
	if _, err := ParseMFAChallengeToken(session, "jwt-secret"); err == nil {
		t.Fatal("session token must not be accepted as a challenge token")
	}
}
