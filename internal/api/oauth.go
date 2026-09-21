package api

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vue-project-backend/internal/auth"
	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

type oauthIdentity struct {
	Email string
	Name  string
}

func oauthCallbackBaseURL(r *http.Request) (scheme, host string) {
	scheme = "https"
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	} else if r.TLS == nil {
		scheme = "http"
	}
	host = strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	return scheme, host
}

func googleOAuthConfig(cfg config.Config, r *http.Request) auth.GoogleOAuthConfig {
	redirectURL := strings.TrimSpace(cfg.GoogleRedirectURL)
	if redirectURL == "" && r != nil {
		scheme, host := oauthCallbackBaseURL(r)
		if host != "" {
			redirectURL = scheme + "://" + host + "/api/v1/auth/oauth/google/callback"
		}
	}
	return auth.GoogleOAuthConfig{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  redirectURL,
	}
}

func githubOAuthConfig(cfg config.Config, r *http.Request) auth.GitHubOAuthConfig {
	redirectURL := strings.TrimSpace(cfg.GitHubRedirectURL)
	if redirectURL == "" && r != nil {
		scheme, host := oauthCallbackBaseURL(r)
		if host != "" {
			redirectURL = scheme + "://" + host + "/api/v1/auth/oauth/github/callback"
		}
	}
	return auth.GitHubOAuthConfig{
		ClientID:     cfg.GitHubClientID,
		ClientSecret: cfg.GitHubClientSecret,
		RedirectURL:  redirectURL,
	}
}

func ssoOAuthConfig(cfg config.Config, r *http.Request) auth.OIDCOAuthConfig {
	redirectURL := strings.TrimSpace(cfg.SSOOIDCRedirectURL)
	if redirectURL == "" && r != nil {
		scheme, host := oauthCallbackBaseURL(r)
		if host != "" {
			redirectURL = scheme + "://" + host + "/api/v1/auth/oauth/sso/callback"
		}
	}
	scopes := splitOAuthScopes(cfg.SSOOIDCScopes)
	return auth.OIDCOAuthConfig{
		Issuer:       cfg.SSOOIDCIssuer,
		ClientID:     cfg.SSOOIDCClientID,
		ClientSecret: cfg.SSOOIDCClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}
}

func splitOAuthScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Fields(raw)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func oauthProviderLabel(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "google":
		return "Google"
	case "github":
		return "GitHub"
	case "sso":
		return "SSO"
	default:
		if provider == "" {
			return "OAuth"
		}
		return strings.ToUpper(provider[:1]) + provider[1:]
	}
}

func oauthProvidersHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		frontendReady := strings.TrimSpace(cfg.FrontendURL) != ""
		googleCfg := googleOAuthConfig(cfg, r)
		githubCfg := githubOAuthConfig(cfg, r)
		ssoCfg := ssoOAuthConfig(cfg, r)
		writeJSON(w, http.StatusOK, map[string]any{
			"google": googleCfg.Enabled() && frontendReady,
			"github": githubCfg.Enabled() && frontendReady,
			"sso":    ssoCfg.Enabled() && frontendReady,
		})
	}
}

func googleOAuthStartHandler(cfg config.Config) http.HandlerFunc {
	return oauthStartHandler(cfg, "google", func(cfg config.Config, r *http.Request, state string) (string, error) {
		return auth.GoogleAuthCodeURL(googleOAuthConfig(cfg, r), state)
	})
}

func githubOAuthStartHandler(cfg config.Config) http.HandlerFunc {
	return oauthStartHandler(cfg, "github", func(cfg config.Config, r *http.Request, state string) (string, error) {
		return auth.GitHubAuthCodeURL(githubOAuthConfig(cfg, r), state)
	})
}

func ssoOAuthStartHandler(cfg config.Config) http.HandlerFunc {
	return oauthStartHandler(cfg, "sso", func(cfg config.Config, r *http.Request, state string) (string, error) {
		return auth.OIDCAuthCodeURL(r.Context(), ssoOAuthConfig(cfg, r), state)
	})
}

func oauthStartHandler(
	cfg config.Config,
	provider string,
	buildURL func(cfg config.Config, r *http.Request, state string) (string, error),
) http.HandlerFunc {
	label := oauthProviderLabel(provider)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if strings.TrimSpace(cfg.FrontendURL) == "" {
			writeError(w, http.StatusServiceUnavailable, "FRONTEND_URL is not configured")
			return
		}

		remember := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("remember")), "1") ||
			strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("remember")), "true")
		redirect := strings.TrimSpace(r.URL.Query().Get("redirect"))

		state, err := auth.NewOAuthState(provider, redirect, remember)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to start "+label+" sign-in")
			return
		}
		encoded, err := auth.EncodeOAuthState(state, cfg.JWTSecret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to start "+label+" sign-in")
			return
		}
		authURL, err := buildURL(cfg, r, encoded)
		if err != nil {
			log.Printf("[auth] %s oauth start failed: %v", provider, err)
			writeError(w, http.StatusServiceUnavailable, label+" sign-in is not configured")
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func googleOAuthCallbackHandler(cfg config.Config, users store.UserStore, auditLogs store.AuditLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handleOAuthCallback(w, r, cfg, users, auditLogs, "google", func() (oauthIdentity, error) {
			profile, err := auth.ExchangeGoogleCode(r.Context(), googleOAuthConfig(cfg, r), strings.TrimSpace(r.URL.Query().Get("code")))
			if err != nil {
				return oauthIdentity{}, err
			}
			return oauthIdentity{Email: profile.Email, Name: profile.Name}, nil
		})
	}
}

func githubOAuthCallbackHandler(cfg config.Config, users store.UserStore, auditLogs store.AuditLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handleOAuthCallback(w, r, cfg, users, auditLogs, "github", func() (oauthIdentity, error) {
			profile, err := auth.ExchangeGitHubCode(r.Context(), githubOAuthConfig(cfg, r), strings.TrimSpace(r.URL.Query().Get("code")))
			if err != nil {
				return oauthIdentity{}, err
			}
			return oauthIdentity{Email: profile.Email, Name: profile.Name}, nil
		})
	}
}

func ssoOAuthCallbackHandler(cfg config.Config, users store.UserStore, auditLogs store.AuditLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handleOAuthCallback(w, r, cfg, users, auditLogs, "sso", func() (oauthIdentity, error) {
			profile, err := auth.ExchangeOIDCCode(r.Context(), ssoOAuthConfig(cfg, r), strings.TrimSpace(r.URL.Query().Get("code")))
			if err != nil {
				return oauthIdentity{}, err
			}
			return oauthIdentity{Email: profile.Email, Name: profile.Name}, nil
		})
	}
}

func handleOAuthCallback(
	w http.ResponseWriter,
	r *http.Request,
	cfg config.Config,
	users store.UserStore,
	auditLogs store.AuditLogStore,
	provider string,
	exchange func() (oauthIdentity, error),
) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	frontend := strings.TrimSpace(cfg.FrontendURL)
	if frontend == "" {
		writeError(w, http.StatusServiceUnavailable, "FRONTEND_URL is not configured")
		return
	}

	label := oauthProviderLabel(provider)

	if errParam := strings.TrimSpace(r.URL.Query().Get("error")); errParam != "" {
		redirectOAuthError(w, r, frontend, label+" sign-in was cancelled or denied.")
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	stateRaw := strings.TrimSpace(r.URL.Query().Get("state"))
	if code == "" || stateRaw == "" {
		redirectOAuthError(w, r, frontend, "Invalid "+label+" sign-in response.")
		return
	}

	state, err := auth.DecodeOAuthState(stateRaw, cfg.JWTSecret)
	if err != nil || !strings.EqualFold(state.Provider, provider) {
		redirectOAuthError(w, r, frontend, label+" sign-in session expired. Please try again.")
		return
	}

	identity, err := exchange()
	if err != nil {
		log.Printf("[auth] %s oauth exchange failed: %v", provider, err)
		redirectOAuthError(w, r, frontend, "Could not verify your "+label+" account. Please try again.")
		return
	}

	user, err := resolveOAuthUser(r, users, auditLogs, identity, label)
	if err != nil {
		redirectOAuthError(w, r, frontend, err.Error())
		return
	}

	ttl := time.Duration(cfg.JWTTTLHours) * time.Hour
	token, err := auth.IssueUserToken(auth.UserIdentity{
		ID:    user.ID,
		Email: user.Email,
		Name:  user.Name,
		Role:  user.Role,
	}, cfg.JWTSecret, ttl)
	if err != nil {
		log.Printf("[auth] %s oauth jwt issue failed user=%d: %v", provider, user.ID, err)
		redirectOAuthError(w, r, frontend, "Sign-in failed. Please try again.")
		return
	}

	logLoginAttempt(r.Context(), auditLogs, r, user, true, http.StatusOK, "Successful "+label+" login")

	params := url.Values{}
	params.Set("token", token)
	params.Set("redirect", state.Redirect)
	if state.Remember {
		params.Set("remember", "1")
	}
	target := frontend + "/login/oauth/callback#" + params.Encode()
	http.Redirect(w, r, target, http.StatusFound)
}

func resolveOAuthUser(
	r *http.Request,
	users store.UserStore,
	auditLogs store.AuditLogStore,
	identity oauthIdentity,
	label string,
) (store.User, error) {
	email := strings.ToLower(strings.TrimSpace(identity.Email))
	name := strings.TrimSpace(identity.Name)
	if email == "" {
		return store.User{}, errOAuthMessage("Sign-in failed. Please try again.")
	}

	user, err := users.FindByEmail(r.Context(), email)
	if err != nil {
		if !store.IsNotFound(err) {
			log.Printf("[auth] %s oauth find user failed: %v", strings.ToLower(label), err)
			return store.User{}, errOAuthMessage("Sign-in failed. Please try again.")
		}
		if name == "" {
			name = strings.Split(email, "@")[0]
		}
		password, genErr := randomOAuthPassword()
		if genErr != nil {
			return store.User{}, errOAuthMessage("Sign-in failed. Please try again.")
		}
		created, createErr := users.Create(r.Context(), store.UserInput{
			Name:     name,
			Email:    email,
			Password: password,
			Role:     "User",
			Status:   "Active",
		})
		if createErr != nil {
			log.Printf("[auth] %s oauth create user failed: %v", strings.ToLower(label), createErr)
			return store.User{}, errOAuthMessage("Could not create your account. Please try again.")
		}
		return created, nil
	}

	if strings.EqualFold(user.Status, "Block") {
		logLoginAttempt(r.Context(), auditLogs, r, user, false, http.StatusForbidden, "Blocked account "+label+" login attempt")
		return store.User{}, errOAuthMessage("Your account is blocked. Please contact an administrator.")
	}

	needsUpdate := false
	nextName := user.Name
	nextStatus := user.Status
	if strings.EqualFold(user.Status, "Waiting") {
		nextStatus = "Active"
		needsUpdate = true
	}
	if name != "" && strings.TrimSpace(user.Name) == "" {
		nextName = name
		needsUpdate = true
	}
	if !needsUpdate {
		return user, nil
	}

	updated, updateErr := users.Update(r.Context(), user.ID, store.UserInput{
		Name:      nextName,
		Email:     user.Email,
		Password:  user.Password,
		Role:      user.Role,
		Status:    nextStatus,
		ServerIDs: user.ServerIDs,
	})
	if updateErr != nil {
		log.Printf("[auth] %s oauth activate user failed user=%d: %v", strings.ToLower(label), user.ID, updateErr)
		return store.User{}, errOAuthMessage("Sign-in failed. Please try again.")
	}
	updated.ServerIDs = user.ServerIDs
	return updated, nil
}

type oauthMessageError struct {
	message string
}

func (e oauthMessageError) Error() string { return e.message }

func errOAuthMessage(message string) error {
	return oauthMessageError{message: message}
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, frontend, message string) {
	params := url.Values{}
	params.Set("oauth_error", message)
	http.Redirect(w, r, frontend+"/login?"+params.Encode(), http.StatusFound)
}

func randomOAuthPassword() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "oauth:" + hex.EncodeToString(buf), nil
}
