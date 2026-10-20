package auth

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	TokenTypeUser         = "user"
	TokenTypeMFAChallenge = "mfa_challenge"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

type UserClaims struct {
	UserID   int64  `json:"uid"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Typ      string `json:"typ"`
	Remember bool   `json:"rm,omitempty"`
	Method   string `json:"am,omitempty"`
	jwt.RegisteredClaims
}

type UserIdentity struct {
	ID    int64
	Email string
	Name  string
	Role  string
	// SessionID is stored as the JWT `jti`; the API rejects tokens whose session
	// row is missing, expired, or revoked.
	SessionID string
}

// MFAChallenge carries sign-in options from the first factor to the session.
type MFAChallenge struct {
	UserID   int64
	Remember bool
	Method   string
}

func IssueUserToken(user UserIdentity, secret string, ttl time.Duration) (string, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "", errors.New("jwt secret is required")
	}
	if user.ID <= 0 {
		return "", errors.New("user id is required")
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	now := time.Now()
	claims := UserClaims{
		UserID: user.ID,
		Email:  strings.TrimSpace(user.Email),
		Name:   strings.TrimSpace(user.Name),
		Role:   strings.TrimSpace(user.Role),
		Typ:    TokenTypeUser,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        strings.TrimSpace(user.SessionID),
			Subject:   strconv.FormatInt(user.ID, 10),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// IssueMFAChallengeToken proves the password step succeeded for userID. It is
// typed so ParseUserToken rejects it as a session token.
func IssueMFAChallengeToken(userID int64, secret string, ttl time.Duration) (string, error) {
	return IssueMFAChallenge(MFAChallenge{UserID: userID}, secret, ttl)
}

func IssueMFAChallenge(challenge MFAChallenge, secret string, ttl time.Duration) (string, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "", errors.New("jwt secret is required")
	}
	if challenge.UserID <= 0 {
		return "", errors.New("user id is required")
	}
	now := time.Now()
	claims := UserClaims{
		UserID:   challenge.UserID,
		Typ:      TokenTypeMFAChallenge,
		Remember: challenge.Remember,
		Method:   strings.TrimSpace(challenge.Method),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(challenge.UserID, 10),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

func ParseMFAChallengeToken(tokenString, secret string) (int64, error) {
	challenge, err := ParseMFAChallenge(tokenString, secret)
	return challenge.UserID, err
}

func ParseMFAChallenge(tokenString, secret string) (MFAChallenge, error) {
	tokenString = strings.TrimSpace(tokenString)
	secret = strings.TrimSpace(secret)
	if tokenString == "" || secret == "" {
		return MFAChallenge{}, ErrInvalidToken
	}
	parsed, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return MFAChallenge{}, ErrExpiredToken
		}
		return MFAChallenge{}, ErrInvalidToken
	}
	claims, ok := parsed.Claims.(*UserClaims)
	if !ok || !parsed.Valid || claims.Typ != TokenTypeMFAChallenge || claims.UserID <= 0 {
		return MFAChallenge{}, ErrInvalidToken
	}
	return MFAChallenge{UserID: claims.UserID, Remember: claims.Remember, Method: claims.Method}, nil
}

func ParseUserToken(tokenString, secret string) (UserClaims, error) {
	tokenString = strings.TrimSpace(tokenString)
	secret = strings.TrimSpace(secret)
	if tokenString == "" || secret == "" {
		return UserClaims{}, ErrInvalidToken
	}

	parsed, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return UserClaims{}, ErrExpiredToken
		}
		return UserClaims{}, ErrInvalidToken
	}

	claims, ok := parsed.Claims.(*UserClaims)
	if !ok || !parsed.Valid {
		return UserClaims{}, ErrInvalidToken
	}
	if claims.Typ != "" && claims.Typ != TokenTypeUser {
		return UserClaims{}, ErrInvalidToken
	}
	if claims.UserID <= 0 {
		if claims.Subject != "" {
			if id, parseErr := strconv.ParseInt(claims.Subject, 10, 64); parseErr == nil && id > 0 {
				claims.UserID = id
			}
		}
	}
	if claims.UserID <= 0 {
		return UserClaims{}, ErrInvalidToken
	}
	return *claims, nil
}
