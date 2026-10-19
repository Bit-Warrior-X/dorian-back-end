package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

type notificationUpsertPayload struct {
	EventKey   string `json:"eventKey"`
	Kind       string `json:"kind"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Body       string `json:"body"`
	Status     string `json:"status"`
	ReqID      string `json:"reqId"`
	ServerID   *int64 `json:"serverId"`
	ServerName string `json:"serverName"`
	Read       bool   `json:"read"`
	At         string `json:"at"`
}

type notificationKeyPayload struct {
	EventKey string `json:"eventKey"`
}

func requireNotificationUser(w http.ResponseWriter, r *http.Request) (int64, bool) {
	principal, ok := AuthPrincipalFromContext(r.Context())
	if !ok || principal.UserID <= 0 {
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Error:   "unauthorized",
			Message: "Authentication required.",
		})
		return 0, false
	}
	return principal.UserID, true
}

func notificationsListHandler(notifications store.NotificationStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		userID, ok := requireNotificationUser(w, r)
		if !ok {
			return
		}
		limit := 40
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				limit = parsed
			}
		}
		items, err := notifications.ListActive(r.Context(), userID, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load notifications")
			return
		}
		if items == nil {
			items = []store.PanelNotification{}
		}
		writeJSON(w, http.StatusOK, items)
	}
}

func notificationsUpsertHandler(notifications store.NotificationStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		userID, ok := requireNotificationUser(w, r)
		if !ok {
			return
		}
		var payload notificationUpsertPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		at := time.Now().UTC()
		if strings.TrimSpace(payload.At) != "" {
			if parsed, err := time.Parse(time.RFC3339, payload.At); err == nil {
				at = parsed.UTC()
			}
		}
		item, err := notifications.Upsert(r.Context(), userID, store.NotificationInput{
			EventKey:   payload.EventKey,
			Kind:       payload.Kind,
			Severity:   payload.Severity,
			Title:      payload.Title,
			Body:       payload.Body,
			Status:     payload.Status,
			ReqID:      payload.ReqID,
			ServerID:   payload.ServerID,
			ServerName: payload.ServerName,
			Read:       payload.Read,
			At:         at,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to save notification")
			return
		}
		writeJSON(w, http.StatusOK, item)
	}
}

func notificationsReadHandler(notifications store.NotificationStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		userID, ok := requireNotificationUser(w, r)
		if !ok {
			return
		}
		var payload notificationKeyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || strings.TrimSpace(payload.EventKey) == "" {
			writeError(w, http.StatusBadRequest, "eventKey required")
			return
		}
		if err := notifications.MarkRead(r.Context(), userID, payload.EventKey); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to mark notification read")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func notificationsReadAllHandler(notifications store.NotificationStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		userID, ok := requireNotificationUser(w, r)
		if !ok {
			return
		}
		if err := notifications.MarkAllRead(r.Context(), userID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to mark notifications read")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func notificationsDismissHandler(notifications store.NotificationStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		userID, ok := requireNotificationUser(w, r)
		if !ok {
			return
		}
		var payload notificationKeyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || strings.TrimSpace(payload.EventKey) == "" {
			writeError(w, http.StatusBadRequest, "eventKey required")
			return
		}
		if err := notifications.Dismiss(r.Context(), userID, payload.EventKey); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to dismiss notification")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func notificationsDismissAllHandler(notifications store.NotificationStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		userID, ok := requireNotificationUser(w, r)
		if !ok {
			return
		}
		if err := notifications.DismissAll(r.Context(), userID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to clear notifications")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func registerNotificationRoutes(mux *http.ServeMux, notifications store.NotificationStore) {
	mux.HandleFunc("/notifications", notificationsListHandler(notifications))
	mux.HandleFunc("/api/v1/notifications", notificationsListHandler(notifications))
	mux.HandleFunc("/notifications/upsert", notificationsUpsertHandler(notifications))
	mux.HandleFunc("/api/v1/notifications/upsert", notificationsUpsertHandler(notifications))
	mux.HandleFunc("/notifications/read", notificationsReadHandler(notifications))
	mux.HandleFunc("/api/v1/notifications/read", notificationsReadHandler(notifications))
	mux.HandleFunc("/notifications/read-all", notificationsReadAllHandler(notifications))
	mux.HandleFunc("/api/v1/notifications/read-all", notificationsReadAllHandler(notifications))
	mux.HandleFunc("/notifications/dismiss", notificationsDismissHandler(notifications))
	mux.HandleFunc("/api/v1/notifications/dismiss", notificationsDismissHandler(notifications))
	mux.HandleFunc("/notifications/dismiss-all", notificationsDismissAllHandler(notifications))
	mux.HandleFunc("/api/v1/notifications/dismiss-all", notificationsDismissAllHandler(notifications))
}
