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

func googleOAuthConfig(cfg config.Config, r *http.Request) auth.GoogleOAuthConfig {
	redirectURL := strings.TrimSpace(cfg.GoogleRedirectURL)
	if redirectURL == "" && r != nil {
		scheme := "https"
		if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
			scheme = strings.Split(forwarded, ",")[0]
			scheme = strings.TrimSpace(scheme)
		} else if r.TLS == nil {
			scheme = "http"
		}
		host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
		if host == "" {
			host = strings.TrimSpace(r.Host)
		}
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

func oauthProvidersHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		googleCfg := googleOAuthConfig(cfg, r)
		writeJSON(w, http.StatusOK, map[string]any{
			"google": googleCfg.Enabled() && strings.TrimSpace(cfg.FrontendURL) != "",
			"github": false,
			"sso":    false,
		})
	}
}

func googleOAuthStartHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if strings.TrimSpace(cfg.FrontendURL) == "" {
			writeError(w, http.StatusServiceUnavailable, "FRONTEND_URL is not configured")
			return
		}
		googleCfg := googleOAuthConfig(cfg, r)
		if !googleCfg.Enabled() {
			writeError(w, http.StatusServiceUnavailable, "Google sign-in is not configured")
			return
		}

		remember := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("remember")), "1") ||
			strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("remember")), "true")
		redirect := strings.TrimSpace(r.URL.Query().Get("redirect"))

		state, err := auth.NewOAuthState("google", redirect, remember)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to start Google sign-in")
			return
		}
		encoded, err := auth.EncodeOAuthState(state, cfg.JWTSecret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to start Google sign-in")
			return
		}
		authURL, err := auth.GoogleAuthCodeURL(googleCfg, encoded)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Google sign-in is not configured")
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func googleOAuthCallbackHandler(cfg config.Config, users store.UserStore, auditLogs store.AuditLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		frontend := strings.TrimSpace(cfg.FrontendURL)
		if frontend == "" {
			writeError(w, http.StatusServiceUnavailable, "FRONTEND_URL is not configured")
			return
		}

		if errParam := strings.TrimSpace(r.URL.Query().Get("error")); errParam != "" {
			redirectOAuthError(w, r, frontend, "Google sign-in was cancelled or denied.")
			return
		}

		code := strings.TrimSpace(r.URL.Query().Get("code"))
		stateRaw := strings.TrimSpace(r.URL.Query().Get("state"))
		if code == "" || stateRaw == "" {
			redirectOAuthError(w, r, frontend, "Invalid Google sign-in response.")
			return
		}

		state, err := auth.DecodeOAuthState(stateRaw, cfg.JWTSecret)
		if err != nil || !strings.EqualFold(state.Provider, "google") {
			redirectOAuthError(w, r, frontend, "Google sign-in session expired. Please try again.")
			return
		}

		googleCfg := googleOAuthConfig(cfg, r)
		if !googleCfg.Enabled() {
			redirectOAuthError(w, r, frontend, "Google sign-in is not configured.")
			return
		}

		profile, err := auth.ExchangeGoogleCode(r.Context(), googleCfg, code)
		if err != nil {
			log.Printf("[auth] google oauth exchange failed: %v", err)
			redirectOAuthError(w, r, frontend, "Could not verify your Google account. Please try again.")
			return
		}

		user, err := users.FindByEmail(r.Context(), profile.Email)
		if err != nil {
			if !store.IsNotFound(err) {
				log.Printf("[auth] google oauth find user failed: %v", err)
				redirectOAuthError(w, r, frontend, "Sign-in failed. Please try again.")
				return
			}
			name := profile.Name
			if name == "" {
				name = strings.Split(profile.Email, "@")[0]
			}
			password, genErr := randomOAuthPassword()
			if genErr != nil {
				redirectOAuthError(w, r, frontend, "Sign-in failed. Please try again.")
				return
			}
			created, createErr := users.Create(r.Context(), store.UserInput{
				Name:     name,
				Email:    profile.Email,
				Password: password,
				Role:     "User",
				Status:   "Waiting",
			})
			if createErr != nil {
				log.Printf("[auth] google oauth create user failed: %v", createErr)
				redirectOAuthError(w, r, frontend, "Could not create your account. Please try again.")
				return
			}
			logLoginAttempt(r.Context(), auditLogs, r, created, false, http.StatusForbidden, "Google sign-in created waiting account")
			redirectOAuthError(w, r, frontend, "Your account was created and is waiting for admin approval.")
			return
		}

		if strings.EqualFold(user.Status, "Block") {
			logLoginAttempt(r.Context(), auditLogs, r, user, false, http.StatusForbidden, "Blocked account Google login attempt")
			redirectOAuthError(w, r, frontend, "Your account is blocked. Please contact an administrator.")
			return
		}
		if strings.EqualFold(user.Status, "Waiting") {
			logLoginAttempt(r.Context(), auditLogs, r, user, false, http.StatusForbidden, "Waiting account Google login attempt")
			redirectOAuthError(w, r, frontend, "Please wait while admin accept your login.")
			return
		}

		if profile.Name != "" && strings.TrimSpace(user.Name) == "" {
			_, _ = users.Update(r.Context(), user.ID, store.UserInput{
				Name:      profile.Name,
				Email:     user.Email,
				Password:  user.Password,
				Role:      user.Role,
				Status:    user.Status,
				ServerIDs: user.ServerIDs,
			})
			user.Name = profile.Name
		}

		ttl := time.Duration(cfg.JWTTTLHours) * time.Hour
		token, err := auth.IssueUserToken(auth.UserIdentity{
			ID:    user.ID,
			Email: user.Email,
			Name:  user.Name,
			Role:  user.Role,
		}, cfg.JWTSecret, ttl)
		if err != nil {
			log.Printf("[auth] google oauth jwt issue failed user=%d: %v", user.ID, err)
			redirectOAuthError(w, r, frontend, "Sign-in failed. Please try again.")
			return
		}

		logLoginAttempt(r.Context(), auditLogs, r, user, true, http.StatusOK, "Successful Google login")

		params := url.Values{}
		params.Set("token", token)
		params.Set("redirect", state.Redirect)
		if state.Remember {
			params.Set("remember", "1")
		}
		target := frontend + "/login/oauth/callback#" + params.Encode()
		http.Redirect(w, r, target, http.StatusFound)
	}
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
