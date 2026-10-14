package store

import (
	"crypto/subtle"
	"errors"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// MaxPasswordBytes is the bcrypt input limit; longer passwords are rejected
// rather than silently truncated.
const MaxPasswordBytes = 72

var ErrPasswordTooLong = errors.New("password must be at most 72 bytes")

// oauthPlaceholderPrefix marks the random passwords older releases stored for
// accounts created through Google/GitHub/SSO.
const oauthPlaceholderPrefix = "oauth:"

func HashPassword(password string) (string, error) {
	if len(password) > MaxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func IsPasswordTooLong(err error) bool {
	return errors.Is(err, ErrPasswordTooLong)
}

func isBcryptHash(value string) bool {
	if len(value) != 60 {
		return false
	}
	return strings.HasPrefix(value, "$2a$") || strings.HasPrefix(value, "$2b$") || strings.HasPrefix(value, "$2y$")
}

var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

// burnPasswordCheck spends roughly the same time as a real bcrypt comparison so
// unknown emails cannot be distinguished from wrong passwords by latency.
func burnPasswordCheck(password string) {
	dummyHashOnce.Do(func() {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dorian-dummy-password"), bcrypt.DefaultCost)
	})
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
}

func passwordMatches(stored, password string) bool {
	if stored == "" || password == "" {
		burnPasswordCheck(password)
		return false
	}
	if isBcryptHash(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
	}
	// Legacy plaintext row not yet migrated by MigrateLegacyPasswords.
	burnPasswordCheck(password)
	return subtle.ConstantTimeCompare([]byte(stored), []byte(password)) == 1
}
