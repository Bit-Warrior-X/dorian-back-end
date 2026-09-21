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
	"golang.org/x/oauth2/github"
)

type GitHubProfile struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type GitHubOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func (c GitHubOAuthConfig) Enabled() bool {
	return strings.TrimSpace(c.ClientID) != "" &&
		strings.TrimSpace(c.ClientSecret) != "" &&
		strings.TrimSpace(c.RedirectURL) != ""
}

func (c GitHubOAuthConfig) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     strings.TrimSpace(c.ClientID),
		ClientSecret: strings.TrimSpace(c.ClientSecret),
		RedirectURL:  strings.TrimSpace(c.RedirectURL),
		Scopes:       []string{"read:user", "user:email"},
		Endpoint:     github.Endpoint,
	}
}

func GitHubAuthCodeURL(cfg GitHubOAuthConfig, state string) (string, error) {
	if !cfg.Enabled() {
		return "", errors.New("github oauth is not configured")
	}
	return cfg.oauth2Config().AuthCodeURL(state, oauth2.AccessTypeOnline), nil
}

func ExchangeGitHubCode(ctx context.Context, cfg GitHubOAuthConfig, code string) (GitHubProfile, error) {
	if !cfg.Enabled() {
		return GitHubProfile{}, errors.New("github oauth is not configured")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return GitHubProfile{}, errors.New("authorization code is required")
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	token, err := cfg.oauth2Config().Exchange(ctx, code)
	if err != nil {
		return GitHubProfile{}, fmt.Errorf("exchange github code: %w", err)
	}
	client := cfg.oauth2Config().Client(ctx, token)

	profile, err := fetchGitHubUser(ctx, client)
	if err != nil {
		return GitHubProfile{}, err
	}
	email := strings.ToLower(strings.TrimSpace(profile.Email))
	if email == "" {
		email, err = fetchGitHubPrimaryEmail(ctx, client)
		if err != nil {
			return GitHubProfile{}, err
		}
	}
	profile.Email = email
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" {
		profile.Name = strings.TrimSpace(profile.Login)
	}
	if profile.Email == "" {
		return GitHubProfile{}, errors.New("github account email is missing or unverified")
	}
	if profile.ID <= 0 {
		return GitHubProfile{}, errors.New("github account id is missing")
	}
	return profile, nil
}

func fetchGitHubUser(ctx context.Context, client *http.Client) (GitHubProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return GitHubProfile{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return GitHubProfile{}, fmt.Errorf("fetch github user: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return GitHubProfile{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return GitHubProfile{}, fmt.Errorf("github user status %d", resp.StatusCode)
	}
	var profile GitHubProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return GitHubProfile{}, fmt.Errorf("decode github user: %w", err)
	}
	return profile, nil
}

func fetchGitHubPrimaryEmail(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch github emails: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github emails status %d", resp.StatusCode)
	}
	var emails []githubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", fmt.Errorf("decode github emails: %w", err)
	}

	var fallback string
	for _, item := range emails {
		email := strings.ToLower(strings.TrimSpace(item.Email))
		if email == "" || !item.Verified {
			continue
		}
		if item.Primary {
			return email, nil
		}
		if fallback == "" {
			fallback = email
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", errors.New("no verified github email available")
}
