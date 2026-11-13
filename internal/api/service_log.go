package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/remotesvc"
	"vue-project-backend/internal/store"
)

const edgeServiceLogLines = 80

func normalizeEdgeServiceLogName(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "angelos", "sparta", "athens":
		return strings.ToLower(strings.TrimSpace(raw)), true
	default:
		return "", false
	}
}

// handleServerSpartaLog keeps the legacy path working (same as service=sparta).
func handleServerSpartaLog(w http.ResponseWriter, r *http.Request, servers store.ServerStore, serverID int64) {
	writeEdgeServiceLog(w, r, servers, serverID, "sparta")
}

func handleServerServiceLog(w http.ResponseWriter, r *http.Request, servers store.ServerStore, serverID int64) {
	service, ok := normalizeEdgeServiceLogName(r.URL.Query().Get("service"))
	if !ok {
		writeError(w, http.StatusBadRequest, "service must be angelos, sparta, or athens")
		return
	}
	writeEdgeServiceLog(w, r, servers, serverID, service)
}

func writeEdgeServiceLog(w http.ResponseWriter, r *http.Request, servers store.ServerStore, serverID int64, service string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	view, err := servers.GetView(ctx, serverID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "server not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load server")
		return
	}

	lines, err := remotesvc.TailEdgeServiceLog(ctx, sshTargetFromView(view), service, edgeServiceLogLines)
	label := strings.ToUpper(service[:1]) + service[1:]
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": service,
			"lines":   []string{},
			"error":   label + " log is unavailable",
		})
		return
	}
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": service,
		"lines":   lines,
	})
}
