package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"vue-project-backend/internal/auth"
	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

type authKind string

const (
	authKindJWT      authKind = "jwt"
	authKindAPIToken authKind = "api_token"
)

type AuthPrincipal struct {
	UserID     int64
	Email      string
	Name       string
	Role       string
	AuthKind   authKind
	TokenID    int64
	SessionID  string
	MFAEnabled bool
}

type authPrincipalContextKey struct{}

func contextWithAuthPrincipal(ctx context.Context, principal AuthPrincipal) context.Context {
	return context.WithValue(ctx, authPrincipalContextKey{}, principal)
}

func AuthPrincipalFromContext(ctx context.Context) (AuthPrincipal, bool) {
	principal, ok := ctx.Value(authPrincipalContextKey{}).(AuthPrincipal)
	return principal, ok
}

func isPublicAuthPath(method, path string) bool {
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}

	switch path {
	case "/health", "/api/v1/health", "/api/v1/status":
		return method == http.MethodGet || method == http.MethodHead
	case "/auth/login", "/api/v1/auth/login",
		"/auth/login/mfa", "/api/v1/auth/login/mfa":
		return method == http.MethodPost
	case "/auth/password/forgot", "/api/v1/auth/password/forgot",
		"/auth/password/token", "/api/v1/auth/password/token",
		"/auth/password/complete", "/api/v1/auth/password/complete":
		return method == http.MethodPost
	case "/auth/oauth/providers", "/api/v1/auth/oauth/providers",
		"/auth/options", "/api/v1/auth/options":
		return method == http.MethodGet || method == http.MethodHead
	case "/auth/oauth/google/start", "/api/v1/auth/oauth/google/start",
		"/auth/oauth/google/callback", "/api/v1/auth/oauth/google/callback",
		"/auth/oauth/github/start", "/api/v1/auth/oauth/github/start",
		"/auth/oauth/github/callback", "/api/v1/auth/oauth/github/callback",
		"/auth/oauth/sso/start", "/api/v1/auth/oauth/sso/start",
		"/auth/oauth/sso/callback", "/api/v1/auth/oauth/sso/callback":
		return method == http.MethodGet
	case "/report_xdp", "/api/report_xdp", "/api/v1/report_xdp":
		return method == http.MethodPost
	case "/report_edge_configure", "/api/report_edge_configure", "/api/v1/report_edge_configure":
		return method == http.MethodPost
	case "/api/get_blocklist_ips", "/api/v1/get_blocklist_ips",
		"/api/get_whitelist_ips", "/api/v1/get_whitelist_ips":
		return method == http.MethodGet || method == http.MethodPost
	case "/temporary_blacklist_added", "/api/temporary_blacklist_added", "/api/v1/temporary_blacklist_added":
		return method == http.MethodPost
	default:
		return false
	}
}

func extractBearerOrAPIKey(r *http.Request) string {
	if raw := strings.TrimSpace(r.Header.Get("Authorization")); raw != "" {
		parts := strings.SplitN(raw, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	if key := strings.TrimSpace(r.Header.Get("X-API-Key")); key != "" {
		return key
	}
	// Browser WebSocket cannot set Authorization headers. Allow token via query
	// only on WebSocket upgrade requests (e.g. access-log stream).
	if isWebSocketUpgrade(r) {
		if q := strings.TrimSpace(r.URL.Query().Get("access_token")); q != "" {
			return q
		}
		if q := strings.TrimSpace(r.URL.Query().Get("token")); q != "" {
			return q
		}
	}
	return ""
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket")
}

// mfaSetupAllowed lists what a user who must enroll in 2FA can still reach:
// enough of the Profile page to finish setup, plus sign-out.
func mfaSetupAllowed(method, path string, userID int64) bool {
	p := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1"), "/")
	switch p {
	case "/auth/logout", "/auth/mfa/setup", "/auth/mfa/enable":
		return true
	case "/auth/mfa", "/auth/me", "/auth/sessions", "/audit-logs", "/auth/api-tokens", "/notifications", "/license-plans":
		return isReadMethod(method)
	}
	if strings.HasPrefix(p, "/auth/sessions/") {
		return true
	}
	if id, ok := parseID(p, "/users/"); ok && id == userID {
		return isReadMethod(method)
	}
	return false
}

func writeMFASetupRequired(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, errorResponse{
		Error:   "mfa_setup_required",
		Message: "Your organization requires two-factor authentication. Set it up on your Profile to continue.",
	})
}

func requireMFAPolicy(r *http.Request, settings store.PanelSettingsStore) string {
	if settings == nil {
		return store.RequireMFAOff
	}
	value, err := settings.Get(r.Context(), store.SettingRequireMFA)
	if err != nil {
		return store.RequireMFAOff
	}
	return store.NormalizeRequireMFA(value)
}

func withAuth(cfg config.Config, apiTokens store.APITokenStore, sessions store.AuthSessionStore, settings store.PanelSettingsStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || isPublicAuthPath(r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		raw := extractBearerOrAPIKey(r)
		if raw == "" {
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error:   "unauthorized",
				Message: "Authentication required.",
			})
			return
		}

		if strings.HasPrefix(raw, store.APITokenPrefix) {
			if apiTokens == nil {
				writeJSON(w, http.StatusUnauthorized, errorResponse{
					Error:   "unauthorized",
					Message: "Invalid or expired API token.",
				})
				return
			}
			lookup, err := apiTokens.LookupActiveBySecret(r.Context(), raw)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, errorResponse{
					Error:   "unauthorized",
					Message: "Invalid or expired API token.",
				})
				return
			}
			if !apiTokenAllows(lookup.Token.Scopes, r.Method, r.URL.Path) {
				writeJSON(w, http.StatusForbidden, errorResponse{
					Error:   "insufficient_scope",
					Message: "This API token's scopes do not allow this request.",
				})
				return
			}
			if store.RequireMFAApplies(requireMFAPolicy(r, settings), lookup.User.Role) && !lookup.User.MFAEnabled {
				writeJSON(w, http.StatusForbidden, errorResponse{
					Error:   "mfa_setup_required",
					Message: "Two-factor authentication is required for this account. API tokens are paused until it is enabled.",
				})
				return
			}
			_ = apiTokens.TouchLastUsed(r.Context(), lookup.Token.ID)
			principal := AuthPrincipal{
				UserID:     lookup.User.ID,
				Email:      lookup.User.Email,
				Name:       lookup.User.Name,
				Role:       lookup.User.Role,
				AuthKind:   authKindAPIToken,
				TokenID:    lookup.Token.ID,
				MFAEnabled: lookup.User.MFAEnabled,
			}
			next.ServeHTTP(w, r.WithContext(contextWithAuthPrincipal(r.Context(), principal)))
			return
		}

		claims, err := auth.ParseUserToken(raw, cfg.JWTSecret)
		if err != nil {
			message := "Invalid or expired session token."
			if err == auth.ErrExpiredToken {
				message = "Session expired. Please sign in again."
			}
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error:   "unauthorized",
				Message: message,
			})
			return
		}

		principal := AuthPrincipal{
			UserID:    claims.UserID,
			Email:     claims.Email,
			Name:      claims.Name,
			Role:      claims.Role,
			AuthKind:  authKindJWT,
			SessionID: claims.ID,
		}
		if sessions != nil {
			lookup, err := sessions.LookupActive(r.Context(), claims.ID)
			if err != nil || lookup.UserID != claims.UserID {
				if err != nil && !store.IsNotFound(err) {
					writeError(w, http.StatusInternalServerError, "failed to verify session")
					return
				}
				writeJSON(w, http.StatusUnauthorized, errorResponse{
					Error:   "session_ended",
					Message: "Your session has ended. Please sign in again.",
				})
				return
			}
			if !strings.EqualFold(lookup.Status, "Active") {
				writeJSON(w, http.StatusUnauthorized, errorResponse{
					Error:   "account_inactive",
					Message: "Your account is not active. Please contact an administrator.",
				})
				return
			}
			_ = sessions.Touch(r.Context(), lookup.Session.ID)
			principal.Email = lookup.Email
			principal.Name = lookup.Name
			principal.Role = lookup.Role
			principal.MFAEnabled = lookup.MFAEnabled
			if store.RequireMFAApplies(requireMFAPolicy(r, settings), lookup.Role) && !lookup.MFAEnabled &&
				!mfaSetupAllowed(r.Method, r.URL.Path, lookup.UserID) {
				writeMFASetupRequired(w)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(contextWithAuthPrincipal(r.Context(), principal)))
	})
}

func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := AuthPrincipalFromContext(r.Context())
		if !ok || !strings.EqualFold(principal.Role, "Admin") {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:   "forbidden",
				Message: "Administrator access required.",
			})
			return
		}
		next(w, r)
	}
}

// requireAdminOrSelfUser allows Admins full access to /users/{id}, and allows
// authenticated users to read/update their own record (not delete).
func requireAdminOrSelfUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := AuthPrincipalFromContext(r.Context())
		if !ok || principal.UserID <= 0 {
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error:   "unauthorized",
				Message: "Authentication required.",
			})
			return
		}
		if strings.EqualFold(principal.Role, "Admin") {
			next(w, r)
			return
		}

		id, parsed := parseID(r.URL.Path, "/users/")
		if !parsed {
			id, parsed = parseID(r.URL.Path, "/api/v1/users/")
		}
		if !parsed || id != principal.UserID {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:   "forbidden",
				Message: "Administrator access required.",
			})
			return
		}
		if r.Method == http.MethodDelete {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:   "forbidden",
				Message: "Administrator access required.",
			})
			return
		}
		next(w, r)
	}
}

// requireAdminOrOwnAuditLogs allows Admins to query any audit history, and allows
// users to query only their own logs via actorUserId=<self>.
func requireAdminOrOwnAuditLogs(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := AuthPrincipalFromContext(r.Context())
		if !ok || principal.UserID <= 0 {
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error:   "unauthorized",
				Message: "Authentication required.",
			})
			return
		}
		if strings.EqualFold(principal.Role, "Admin") {
			next(w, r)
			return
		}

		raw := strings.TrimSpace(r.URL.Query().Get("actorUserId"))
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed != principal.UserID {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:   "forbidden",
				Message: "Administrator access required.",
			})
			return
		}
		next(w, r)
	}
}
