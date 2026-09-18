package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const oauthStateTTL = 10 * time.Minute

var (
	ErrInvalidOAuthState = errors.New("invalid oauth state")
	ErrExpiredOAuthState = errors.New("expired oauth state")
)

type OAuthState struct {
	Nonce    string `json:"n"`
	Provider string `json:"p"`
	Redirect string `json:"r,omitempty"`
	Remember bool   `json:"m,omitempty"`
	IssuedAt int64  `json:"iat"`
}

func NewOAuthState(provider, redirect string, remember bool) (OAuthState, error) {
	nonce, err := randomNonce(16)
	if err != nil {
		return OAuthState{}, err
	}
	return OAuthState{
		Nonce:    nonce,
		Provider: strings.TrimSpace(provider),
		Redirect: sanitizeOAuthRedirect(redirect),
		Remember: remember,
		IssuedAt: time.Now().Unix(),
	}, nil
}

func EncodeOAuthState(state OAuthState, secret string) (string, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "", errors.New("oauth state secret is required")
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(encodedPayload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encodedPayload + "." + sig, nil
}

func DecodeOAuthState(raw, secret string) (OAuthState, error) {
	secret = strings.TrimSpace(secret)
	raw = strings.TrimSpace(raw)
	if secret == "" || raw == "" {
		return OAuthState{}, ErrInvalidOAuthState
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return OAuthState{}, ErrInvalidOAuthState
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0]))
	expected := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(expected, got) {
		return OAuthState{}, ErrInvalidOAuthState
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return OAuthState{}, ErrInvalidOAuthState
	}
	var state OAuthState
	if err := json.Unmarshal(payload, &state); err != nil {
		return OAuthState{}, ErrInvalidOAuthState
	}
	if state.Nonce == "" || state.Provider == "" || state.IssuedAt <= 0 {
		return OAuthState{}, ErrInvalidOAuthState
	}
	issued := time.Unix(state.IssuedAt, 0)
	if time.Since(issued) > oauthStateTTL || issued.After(time.Now().Add(time.Minute)) {
		return OAuthState{}, ErrExpiredOAuthState
	}
	state.Redirect = sanitizeOAuthRedirect(state.Redirect)
	return state, nil
}

func sanitizeOAuthRedirect(redirect string) string {
	redirect = strings.TrimSpace(redirect)
	if redirect == "" {
		return "/app"
	}
	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		return "/app"
	}
	if strings.ContainsAny(redirect, "\r\n") {
		return "/app"
	}
	return redirect
}

func randomNonce(size int) (string, error) {
	if size <= 0 {
		size = 16
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
