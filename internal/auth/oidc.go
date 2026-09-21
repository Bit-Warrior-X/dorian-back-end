package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type OIDCOAuthConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

type OIDCProfile struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
	Name          string `json:"name"`
	PreferredName string `json:"preferred_username"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

type oidcCacheEntry struct {
	discovery oidcDiscovery
	expires   time.Time
}

var (
	oidcDiscoveryMu    sync.Mutex
	oidcDiscoveryCache = map[string]oidcCacheEntry{}
)

func (c OIDCOAuthConfig) Enabled() bool {
	return strings.TrimSpace(c.Issuer) != "" &&
		strings.TrimSpace(c.ClientID) != "" &&
		strings.TrimSpace(c.ClientSecret) != "" &&
		strings.TrimSpace(c.RedirectURL) != ""
}

func (c OIDCOAuthConfig) scopes() []string {
	if len(c.Scopes) > 0 {
		return c.Scopes
	}
	return []string{"openid", "email", "profile"}
}

func (c OIDCOAuthConfig) oauth2Config(discovery oidcDiscovery) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     strings.TrimSpace(c.ClientID),
		ClientSecret: strings.TrimSpace(c.ClientSecret),
		RedirectURL:  strings.TrimSpace(c.RedirectURL),
		Scopes:       c.scopes(),
		Endpoint: oauth2.Endpoint{
			AuthURL:  discovery.AuthorizationEndpoint,
			TokenURL: discovery.TokenEndpoint,
		},
	}
}

func OIDCAuthCodeURL(ctx context.Context, cfg OIDCOAuthConfig, state string) (string, error) {
	if !cfg.Enabled() {
		return "", errors.New("sso oidc is not configured")
	}
	discovery, err := discoverOIDC(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}
	return cfg.oauth2Config(discovery).AuthCodeURL(state, oauth2.AccessTypeOnline), nil
}

func ExchangeOIDCCode(ctx context.Context, cfg OIDCOAuthConfig, code string) (OIDCProfile, error) {
	if !cfg.Enabled() {
		return OIDCProfile{}, errors.New("sso oidc is not configured")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return OIDCProfile{}, errors.New("authorization code is required")
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	discovery, err := discoverOIDC(ctx, cfg.Issuer)
	if err != nil {
		return OIDCProfile{}, err
	}
	if strings.TrimSpace(discovery.UserInfoEndpoint) == "" {
		return OIDCProfile{}, errors.New("oidc provider does not expose userinfo_endpoint")
	}

	token, err := cfg.oauth2Config(discovery).Exchange(ctx, code)
	if err != nil {
		return OIDCProfile{}, fmt.Errorf("exchange oidc code: %w", err)
	}

	client := cfg.oauth2Config(discovery).Client(ctx, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery.UserInfoEndpoint, nil)
	if err != nil {
		return OIDCProfile{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return OIDCProfile{}, fmt.Errorf("fetch oidc userinfo: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return OIDCProfile{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return OIDCProfile{}, fmt.Errorf("oidc userinfo status %d", resp.StatusCode)
	}

	var profile OIDCProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return OIDCProfile{}, fmt.Errorf("decode oidc userinfo: %w", err)
	}
	profile.Email = strings.ToLower(strings.TrimSpace(profile.Email))
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" {
		profile.Name = strings.TrimSpace(strings.TrimSpace(profile.GivenName) + " " + strings.TrimSpace(profile.FamilyName))
	}
	if profile.Name == "" {
		profile.Name = strings.TrimSpace(profile.PreferredName)
	}
	if profile.Email == "" {
		return OIDCProfile{}, errors.New("oidc account email is missing")
	}
	if !oidcEmailVerified(profile.EmailVerified) {
		return OIDCProfile{}, errors.New("oidc account email is unverified")
	}
	if strings.TrimSpace(profile.Sub) == "" {
		return OIDCProfile{}, errors.New("oidc account id is missing")
	}
	return profile, nil
}

func oidcEmailVerified(value any) bool {
	switch v := value.(type) {
	case nil:
		// Some IdPs omit the claim even when email is trusted; allow when claim is absent.
		return true
	case bool:
		return v
	case string:
		normalized := strings.ToLower(strings.TrimSpace(v))
		return normalized == "true" || normalized == "1"
	case float64:
		return v != 0
	default:
		return true
	}
}

func discoverOIDC(ctx context.Context, issuer string) (oidcDiscovery, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return oidcDiscovery{}, errors.New("oidc issuer is required")
	}

	oidcDiscoveryMu.Lock()
	if entry, ok := oidcDiscoveryCache[issuer]; ok && time.Now().Before(entry.expires) {
		discovery := entry.discovery
		oidcDiscoveryMu.Unlock()
		return discovery, nil
	}
	oidcDiscoveryMu.Unlock()

	discoveryURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return oidcDiscovery{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oidcDiscovery{}, fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return oidcDiscovery{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return oidcDiscovery{}, fmt.Errorf("oidc discovery status %d", resp.StatusCode)
	}
	var discovery oidcDiscovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return oidcDiscovery{}, fmt.Errorf("decode oidc discovery: %w", err)
	}
	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" {
		return oidcDiscovery{}, errors.New("oidc discovery missing authorization/token endpoints")
	}

	oidcDiscoveryMu.Lock()
	oidcDiscoveryCache[issuer] = oidcCacheEntry{
		discovery: discovery,
		expires:   time.Now().Add(30 * time.Minute),
	}
	oidcDiscoveryMu.Unlock()
	return discovery, nil
}
