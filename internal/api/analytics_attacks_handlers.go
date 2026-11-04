package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

type analyticsAttacksResponse struct {
	Items   []store.SecurityEventPeriod `json:"items"`
	Offset  int                         `json:"offset"`
	Limit   int                         `json:"limit"`
	HasMore bool                        `json:"hasMore"`
	Layer   string                      `json:"layer,omitempty"`
}

// analyticsAttacksHandler is the panel attack inbox: paginated L4+L7 periods with
// reqId for Attack Console deep-links. Prefer this over dual /dashboard/security-events
// + /analytics/l4|security/attacks/* fan-out for Security events UI.
func analyticsAttacksHandler(securityEvents store.SecurityEventStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		limit := 25
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				writeError(w, http.StatusBadRequest, "invalid limit")
				return
			}
			limit = parsed
		}
		if limit > 200 {
			limit = 200
		}

		offset := 0
		if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 {
				writeError(w, http.StatusBadRequest, "invalid offset")
				return
			}
			offset = parsed
		}

		layer := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("layer")))
		if layer != "" && layer != "l4" && layer != "l7" {
			writeError(w, http.StatusBadRequest, "invalid layer")
			return
		}

		var windowStart, windowEnd time.Time
		hasWindow := strings.TrimSpace(r.URL.Query().Get("start")) != "" ||
			strings.TrimSpace(r.URL.Query().Get("end")) != "" ||
			strings.TrimSpace(r.URL.Query().Get("range")) != ""
		if hasWindow {
			start, end, err := parseAnalyticsWindow(r)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid time range")
				return
			}
			windowStart, windowEnd = start, end
		}

		scope, err := parseDashboardScope(r, sites)
		if err != nil {
			if isScopeNotFound(err) {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Periods are edge-scoped (no site column); keep site→server ACL from parseDashboardScope
		// then drop SiteID so we do not pretend floods are per-site.
		scope = stripSiteScope(scope)

		// Fetch one extra row to detect hasMore without a separate COUNT.
		page, err := securityEvents.ListPeriodsPage(r.Context(), offset, limit+1, scope, windowStart, windowEnd, layer)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load attacks")
			return
		}
		hasMore := len(page) > limit
		if hasMore {
			page = page[:limit]
		}

		writeJSON(w, http.StatusOK, analyticsAttacksResponse{
			Items:   page,
			Offset:  offset,
			Limit:   limit,
			HasMore: hasMore,
			Layer:   layer,
		})
	}
}
