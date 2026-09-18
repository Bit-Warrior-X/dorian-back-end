package auth

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const TokenTypeUser = "user"

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

type UserClaims struct {
	UserID int64  `json:"uid"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Role   string `json:"role"`
	Typ    string `json:"typ"`
	jwt.RegisteredClaims
}

type UserIdentity struct {
	ID    int64
	Email string
	Name  string
	Role  string
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
