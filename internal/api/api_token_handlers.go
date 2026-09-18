package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

type apiTokenCreateRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expiresAt"`
}

func apiTokensHandler(apiTokens store.APITokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := AuthPrincipalFromContext(r.Context())
		if !ok || principal.UserID <= 0 {
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error:   "unauthorized",
				Message: "Authentication required.",
			})
			return
		}

		switch r.Method {
		case http.MethodGet:
			items, err := apiTokens.ListByUser(r.Context(), principal.UserID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load API tokens")
				return
			}
			if items == nil {
				items = []store.APIToken{}
			}
			writeJSON(w, http.StatusOK, items)
		case http.MethodPost:
			var payload apiTokenCreateRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			name := strings.TrimSpace(payload.Name)
			if name == "" {
				writeError(w, http.StatusBadRequest, "name is required")
				return
			}
			var expiresAt *time.Time
			if payload.ExpiresAt != nil && strings.TrimSpace(*payload.ExpiresAt) != "" {
				parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*payload.ExpiresAt))
				if err != nil {
					writeError(w, http.StatusBadRequest, "expiresAt must be RFC3339")
					return
				}
				utc := parsed.UTC()
				expiresAt = &utc
			}
			created, err := apiTokens.Create(r.Context(), store.APITokenCreateInput{
				UserID:    principal.UserID,
				Name:      name,
				Scopes:    payload.Scopes,
				ExpiresAt: expiresAt,
			})
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, map[string]any{
				"token":  created.Token,
				"secret": created.Secret,
			})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func apiTokenDetailHandler(apiTokens store.APITokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := AuthPrincipalFromContext(r.Context())
		if !ok || principal.UserID <= 0 {
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error:   "unauthorized",
				Message: "Authentication required.",
			})
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/api/v1/auth/api-tokens/")
		path = strings.TrimPrefix(path, "/auth/api-tokens/")
		path = strings.Trim(path, "/")
		if path == "" {
			writeError(w, http.StatusBadRequest, "token id is required")
			return
		}
		tokenID, err := strconv.ParseInt(path, 10, 64)
		if err != nil || tokenID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid token id")
			return
		}
		if err := apiTokens.Revoke(r.Context(), principal.UserID, tokenID); err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusNotFound, "token not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to revoke token")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
