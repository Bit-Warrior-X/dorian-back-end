package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleProfile struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func (c GoogleOAuthConfig) Enabled() bool {
	return strings.TrimSpace(c.ClientID) != "" &&
		strings.TrimSpace(c.ClientSecret) != "" &&
		strings.TrimSpace(c.RedirectURL) != ""
}

func (c GoogleOAuthConfig) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     strings.TrimSpace(c.ClientID),
		ClientSecret: strings.TrimSpace(c.ClientSecret),
		RedirectURL:  strings.TrimSpace(c.RedirectURL),
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}
}

func GoogleAuthCodeURL(cfg GoogleOAuthConfig, state string) (string, error) {
	if !cfg.Enabled() {
		return "", errors.New("google oauth is not configured")
	}
	return cfg.oauth2Config().AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.SetAuthURLParam("prompt", "select_account")), nil
}

func ExchangeGoogleCode(ctx context.Context, cfg GoogleOAuthConfig, code string) (GoogleProfile, error) {
	if !cfg.Enabled() {
		return GoogleProfile{}, errors.New("google oauth is not configured")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return GoogleProfile{}, errors.New("authorization code is required")
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	token, err := cfg.oauth2Config().Exchange(ctx, code)
	if err != nil {
		return GoogleProfile{}, fmt.Errorf("exchange google code: %w", err)
	}
	client := cfg.oauth2Config().Client(ctx, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	if err != nil {
		return GoogleProfile{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return GoogleProfile{}, fmt.Errorf("fetch google userinfo: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return GoogleProfile{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return GoogleProfile{}, fmt.Errorf("google userinfo status %d", resp.StatusCode)
	}
	var profile GoogleProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return GoogleProfile{}, fmt.Errorf("decode google userinfo: %w", err)
	}
	profile.Email = strings.ToLower(strings.TrimSpace(profile.Email))
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" {
		profile.Name = strings.TrimSpace(strings.TrimSpace(profile.GivenName) + " " + strings.TrimSpace(profile.FamilyName))
	}
	if profile.Email == "" || !profile.EmailVerified {
		return GoogleProfile{}, errors.New("google account email is missing or unverified")
	}
	if profile.Sub == "" {
		return GoogleProfile{}, errors.New("google account id is missing")
	}
	return profile, nil
}
