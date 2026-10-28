package api

import (
	"context"
	"net/http"
	"time"

	"vue-project-backend/internal/remotesvc"
	"vue-project-backend/internal/store"
)

func handleServerSpartaLog(w http.ResponseWriter, r *http.Request, servers store.ServerStore, serverID int64) {
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

	target := sshTargetFromView(view)
	lines, err := remotesvc.TailSpartaLatestLog(ctx, target, 80)
	if err != nil || len(lines) == 0 {
		// Fall back to journal for edges that have not moved off systemd logging yet.
		if journal, journalErr := remotesvc.TailServiceJournal(ctx, target, "sparta", 80); journalErr == nil && len(journal) > 0 {
			lines, err = journal, nil
		}
	}
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"lines": []string{},
			"error": "Sparta log is unavailable",
		})
		return
	}
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines})
}
