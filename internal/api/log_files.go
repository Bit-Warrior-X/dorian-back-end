package api

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/remotesvc"
	"vue-project-backend/internal/store"
)

const (
	logFilesPageDefault = 200
	logFilesPageMax     = 500
	logFilesListTimeout = 25 * time.Second
	logFilesReadTimeout = 30 * time.Second
	// Soft warn threshold so the UI can flag attack-sized hours.
	logFilesAttackHintL7 = 100 * 1024 * 1024 // 100 MiB
	logFilesAttackHintL4 = 1 * 1024 * 1024   // 1 MiB
)

type logFileListItem struct {
	Layer      string `json:"layer"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	SizeBytes  int64  `json:"sizeBytes"`
	SizeLabel  string `json:"sizeLabel"`
	Hour       string `json:"hour,omitempty"`
	ModTime    string `json:"modTime,omitempty"`
	AttackHint bool   `json:"attackHint"`
}

type logFileContentResponse struct {
	ServerID int64    `json:"serverId"`
	Path     string   `json:"path"`
	Name     string   `json:"name"`
	Total    int      `json:"total"`
	Offset   int      `json:"offset"`
	Limit    int      `json:"limit"`
	Next     int      `json:"next"`
	HasMore  bool     `json:"hasMore"`
	Lines    []string `json:"lines"`
	Error    string   `json:"error,omitempty"`
}

func analyticsLogFilesHandler(servers store.ServerStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		serverID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("serverId")), 10, 64)
		if err != nil || serverID <= 0 {
			writeError(w, http.StatusBadRequest, "serverId is required")
			return
		}
		viewer := viewerScopeFromContext(r.Context())
		if !viewer.canSeeServer(serverID) {
			writeError(w, http.StatusNotFound, "server not found")
			return
		}
		layer := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("layer")))
		if layer == "" {
			layer = "all"
		}

		view, ok := loadServerViewOrWriteError(w, r, servers, serverID)
		if !ok {
			return
		}
		listCtx, cancel := context.WithTimeout(r.Context(), logFilesListTimeout)
		files, listErr := remotesvc.ListEdgeHourlyLogs(listCtx, sshTargetFromView(view), layer)
		cancel()
		if listErr != nil {
			writeError(w, http.StatusBadGateway, "could not list edge log files")
			return
		}
		items := make([]logFileListItem, 0, len(files))
		for _, f := range files {
			item := logFileListItem{
				Layer:      f.Layer,
				Kind:       f.Kind,
				Name:       f.Name,
				Path:       f.Path,
				SizeBytes:  f.SizeBytes,
				SizeLabel:  formatByteSize(f.SizeBytes),
				Hour:       f.Hour,
				AttackHint: edgeLogAttackHint(f.Layer, f.Kind, f.SizeBytes),
			}
			if !f.ModTime.IsZero() {
				item.ModTime = f.ModTime.UTC().Format(time.RFC3339)
			}
			items = append(items, item)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"serverId": serverID,
			"layer":    layer,
			"files":    items,
			"roots": map[string]string{
				"l4": "/usr/local/share/dorian/sparta/logs",
				"l7": "/usr/local/share/dorian/athens/nginx/logs/access",
			},
		})
	}
}

func analyticsLogFilesContentHandler(servers store.ServerStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		serverID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("serverId")), 10, 64)
		if err != nil || serverID <= 0 {
			writeError(w, http.StatusBadRequest, "serverId is required")
			return
		}
		filePath := strings.TrimSpace(r.URL.Query().Get("path"))
		if filePath == "" {
			writeError(w, http.StatusBadRequest, "path is required")
			return
		}
		if !remotesvc.AllowedEdgeLogPath(filePath) {
			writeError(w, http.StatusBadRequest, "path outside allowed log directories")
			return
		}
		viewer := viewerScopeFromContext(r.Context())
		if !viewer.canSeeServer(serverID) {
			writeError(w, http.StatusNotFound, "server not found")
			return
		}
		offset, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("offset")))
		if offset < 0 {
			offset = 0
		}
		limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
		if limit <= 0 {
			limit = logFilesPageDefault
		}
		if limit > logFilesPageMax {
			limit = logFilesPageMax
		}
		skipTotal := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("skipTotal")), "1") ||
			strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("skipTotal")), "true")

		view, ok := loadServerViewOrWriteError(w, r, servers, serverID)
		if !ok {
			return
		}
		readCtx, cancel := context.WithTimeout(r.Context(), logFilesReadTimeout)
		page, readErr := remotesvc.ReadEdgeHourlyLogPage(readCtx, sshTargetFromView(view), filePath, offset, limit, skipTotal)
		cancel()
		if readErr != nil {
			writeJSON(w, http.StatusOK, logFileContentResponse{
				ServerID: serverID,
				Path:     filePath,
				Name:     path.Base(filePath),
				Offset:   offset,
				Limit:    limit,
				Lines:    []string{},
				Error:    "log file is unavailable",
			})
			return
		}
		next := offset + len(page.Lines)
		writeJSON(w, http.StatusOK, logFileContentResponse{
			ServerID: serverID,
			Path:     page.Path,
			Name:     page.Name,
			Total:    page.Total,
			Offset:   page.Offset,
			Limit:    page.Limit,
			Next:     next,
			HasMore:  page.HasMore,
			Lines:    page.Lines,
		})
	}
}

func analyticsLogFilesDownloadHandler(servers store.ServerStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		serverID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("serverId")), 10, 64)
		if err != nil || serverID <= 0 {
			writeError(w, http.StatusBadRequest, "serverId is required")
			return
		}
		filePath := strings.TrimSpace(r.URL.Query().Get("path"))
		if filePath == "" || !remotesvc.AllowedEdgeLogPath(filePath) {
			writeError(w, http.StatusBadRequest, "path outside allowed log directories")
			return
		}
		viewer := viewerScopeFromContext(r.Context())
		if !viewer.canSeeServer(serverID) {
			writeError(w, http.StatusNotFound, "server not found")
			return
		}
		view, ok := loadServerViewOrWriteError(w, r, servers, serverID)
		if !ok {
			return
		}
		target := sshTargetFromView(view)
		statCtx, cancelStat := context.WithTimeout(r.Context(), 10*time.Second)
		size, statErr := remotesvc.StatEdgeHourlyLog(statCtx, target, filePath)
		cancelStat()
		if statErr != nil {
			writeError(w, http.StatusBadGateway, "could not read log file")
			return
		}
		if size <= 0 {
			writeError(w, http.StatusNotFound, "log file not found")
			return
		}

		name := path.Base(filePath)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
		w.Header().Set("X-Log-Path", filePath)
		w.Header().Set("X-Log-Size", strconv.FormatInt(size, 10))
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))

		streamCtx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
		defer cancel()
		if err := remotesvc.StreamEdgeHourlyLog(streamCtx, target, filePath, w); err != nil {
			// Headers may already be flushed; nothing useful to write.
			return
		}
	}
}

func edgeLogAttackHint(layer, kind string, size int64) bool {
	if strings.EqualFold(kind, "attack") {
		return true
	}
	switch strings.ToLower(layer) {
	case "l7":
		return size >= logFilesAttackHintL7
	case "l4":
		return size >= logFilesAttackHintL4
	default:
		return false
	}
}

func formatByteSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	val := float64(n)
	for _, unit := range units {
		val /= 1024
		if val < 1024 {
			if val >= 100 {
				return fmt.Sprintf("%.0f %s", val, unit)
			}
			if val >= 10 {
				return fmt.Sprintf("%.1f %s", val, unit)
			}
			return fmt.Sprintf("%.2f %s", val, unit)
		}
	}
	return fmt.Sprintf("%.1f TiB", val)
}
