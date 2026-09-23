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
	UserID   int64
	Email    string
	Name     string
	Role     string
	AuthKind authKind
	TokenID  int64
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
	case "/auth/login", "/api/v1/auth/login":
		return method == http.MethodPost
	case "/auth/oauth/providers", "/api/v1/auth/oauth/providers":
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

func withAuth(cfg config.Config, apiTokens store.APITokenStore, next http.Handler) http.Handler {
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
			_ = apiTokens.TouchLastUsed(r.Context(), lookup.Token.ID)
			principal := AuthPrincipal{
				UserID:   lookup.User.ID,
				Email:    lookup.User.Email,
				Name:     lookup.User.Name,
				Role:     lookup.User.Role,
				AuthKind: authKindAPIToken,
				TokenID:  lookup.Token.ID,
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
			UserID:   claims.UserID,
			Email:    claims.Email,
			Name:     claims.Name,
			Role:     claims.Role,
			AuthKind: authKindJWT,
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
