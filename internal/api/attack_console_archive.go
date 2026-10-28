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

type attackArchiveLine struct {
	Time string `json:"time,omitempty"`
	Text string `json:"text"`
}

type attackArchiveResponse struct {
	ReqID    string              `json:"reqId"`
	ServerID int64               `json:"serverId,omitempty"`
	File     string              `json:"file,omitempty"`
	FileName string              `json:"fileName,omitempty"`
	Total    int                 `json:"total"`
	Offset   int                 `json:"offset"`
	Limit    int                 `json:"limit"`
	Next     int                 `json:"next"`
	HasMore  bool                `json:"hasMore"`
	Lines    []attackArchiveLine `json:"lines"`
	Error    string              `json:"error,omitempty"`
}

const (
	spartaArchivePageDefault = 200
	spartaArchivePageMax     = 500
)

func attackConsoleArchiveHandler(securityEvents store.SecurityEventStore, servers store.ServerStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		reqID := strings.TrimSpace(r.URL.Query().Get("reqId"))
		if reqID == "" {
			writeError(w, http.StatusBadRequest, "reqId is required")
			return
		}
		offset, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("offset")))
		if offset < 0 {
			offset = 0
		}
		limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
		if limit <= 0 {
			limit = spartaArchivePageDefault
		}
		if limit > spartaArchivePageMax {
			limit = spartaArchivePageMax
		}
		skipTotal := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("skipTotal")), "1") ||
			strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("skipTotal")), "true")

		period, err := securityEvents.GetPeriod(r.Context(), reqID)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusNotFound, "attack not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to load attack")
			return
		}
		viewer := viewerScopeFromContext(r.Context())
		serverID := int64(0)
		if period.ServerID != nil {
			serverID = *period.ServerID
		}
		if serverID > 0 && !viewer.canSeeServer(serverID) {
			writeError(w, http.StatusNotFound, "attack not found")
			return
		}
		if serverID <= 0 {
			writeJSON(w, http.StatusOK, attackArchiveResponse{
				ReqID:   reqID,
				Offset:  offset,
				Limit:   limit,
				Lines:   []attackArchiveLine{},
				Error:   "no edge is linked to this attack",
				HasMore: false,
			})
			return
		}

		viewCtx, cancelView := context.WithTimeout(r.Context(), 3*time.Second)
		view, viewErr := servers.GetView(viewCtx, serverID)
		cancelView()
		if viewErr != nil {
			writeJSON(w, http.StatusOK, attackArchiveResponse{
				ReqID:    reqID,
				ServerID: serverID,
				Offset:   offset,
				Limit:    limit,
				Lines:    []attackArchiveLine{},
				Error:    "edge connection is unavailable",
			})
			return
		}

		logCtx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		page, logErr := remotesvc.ReadSpartaAttackArchivePage(logCtx, sshTargetFromView(view), reqID, offset, limit, skipTotal)
		cancel()
		if logErr != nil {
			writeJSON(w, http.StatusOK, attackArchiveResponse{
				ReqID:    reqID,
				ServerID: serverID,
				Offset:   offset,
				Limit:    limit,
				Lines:    []attackArchiveLine{},
				Error:    "Sparta archive is unavailable",
			})
			return
		}

		periodStart := time.Time{}
		if started, ok := parseConsoleTime(period.StartedAt); ok {
			periodStart = started
		}
		lines := toArchiveFullLogLines(page.Lines, page.EdgeStart, periodStart)
		next := offset + len(lines)
		hasMore := page.HasMore
		if page.Total > 0 {
			hasMore = next < page.Total
		}
		writeJSON(w, http.StatusOK, attackArchiveResponse{
			ReqID:    reqID,
			ServerID: serverID,
			File:     page.File,
			FileName: path.Base(page.File),
			Total:    page.Total,
			Offset:   offset,
			Limit:    limit,
			Next:     next,
			HasMore:  hasMore,
			Lines:    lines,
		})
	}
}

func attackConsoleArchiveDownloadHandler(securityEvents store.SecurityEventStore, servers store.ServerStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		reqID := strings.TrimSpace(r.URL.Query().Get("reqId"))
		if reqID == "" {
			writeError(w, http.StatusBadRequest, "reqId is required")
			return
		}
		period, err := securityEvents.GetPeriod(r.Context(), reqID)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusNotFound, "attack not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to load attack")
			return
		}
		viewer := viewerScopeFromContext(r.Context())
		serverID := int64(0)
		if period.ServerID != nil {
			serverID = *period.ServerID
		}
		if serverID <= 0 || !viewer.canSeeServer(serverID) {
			writeError(w, http.StatusNotFound, "attack not found")
			return
		}

		viewCtx, cancelView := context.WithTimeout(r.Context(), 3*time.Second)
		view, viewErr := servers.GetView(viewCtx, serverID)
		cancelView()
		if viewErr != nil {
			writeError(w, http.StatusBadGateway, "edge connection is unavailable")
			return
		}
		target := sshTargetFromView(view)

		resolveCtx, cancelResolve := context.WithTimeout(r.Context(), 15*time.Second)
		info, resolveErr := remotesvc.ResolveSpartaAttackArchive(resolveCtx, target, reqID)
		cancelResolve()
		if resolveErr != nil {
			writeError(w, http.StatusBadGateway, "Sparta archive is unavailable")
			return
		}
		if strings.TrimSpace(info.Path) == "" {
			writeError(w, http.StatusNotFound, "archive file not found for this attack")
			return
		}

		name := info.Name
		if name == "" {
			name = fmt.Sprintf("sparta-attack-%s.log", reqID)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, strings.ReplaceAll(name, `"`, "")))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if info.Size > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
		}
		w.WriteHeader(http.StatusOK)

		streamCtx, cancelStream := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancelStream()
		if err := remotesvc.StreamSpartaAttackArchive(streamCtx, target, info.Path, w); err != nil {
			// Headers may already be flushed; nothing useful left to write as JSON.
			return
		}
	}
}

func toArchiveFullLogLines(lines []remotesvc.JournalLine, edgeStart, periodStart time.Time) []attackArchiveLine {
	var offset time.Duration
	haveOffset := false
	if !edgeStart.IsZero() && !periodStart.IsZero() {
		offset = periodStart.Sub(edgeStart).Round(time.Minute)
		haveOffset = true
	}
	out := make([]attackArchiveLine, 0, len(lines))
	for _, line := range lines {
		text := line.Message
		at := line.Time
		if match := spartaStamp.FindStringSubmatch(strings.TrimSpace(text)); match != nil {
			if wall, err := time.ParseInLocation("2006-01-02 15:04:05", strings.Replace(match[1], "T", " ", 1), time.UTC); err == nil {
				if haveOffset {
					at = wall.Add(offset)
				} else if !line.Time.IsZero() {
					at = alignEdgeLocalTime(wall, line.Time)
				} else {
					at = alignEdgeLocalTime(wall, time.Now().UTC())
				}
			}
			// Keep the stamp in the text for the full-log viewer.
		} else if haveOffset && !at.IsZero() {
			at = at.Add(offset)
		}
		item := attackArchiveLine{Text: text}
		if !at.IsZero() {
			item.Time = at.UTC().Format(time.RFC3339)
		}
		out = append(out, item)
	}
	return out
}
