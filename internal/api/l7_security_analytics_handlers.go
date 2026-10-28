package api

import (
	"net/http"
	"strconv"
	"strings"

	"vue-project-backend/internal/store"
)

func securityAnalyticsRuleTypesHandler(stats store.ServerTrafficStatsStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		scope, start, end, ok := parseAnalyticsScope(w, r, sites)
		if !ok {
			return
		}
		rows, err := stats.ListBlockReasonRuleTypes(r.Context(), start, end, scope)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load block reason summary")
			return
		}
		if rows == nil {
			rows = []store.BlockReasonRuleRow{}
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

func securityAnalyticsAttackSummaryHandler(events store.L7BlockEventStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		scope, start, end, ok := parseAnalyticsScope(w, r, sites)
		if !ok {
			return
		}
		summary, err := events.Summarize(r.Context(), start, end, scope)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load L7 attack summary")
			return
		}
		writeJSON(w, http.StatusOK, summary)
	}
}

func securityAnalyticsRecentAttacksHandler(events store.L7BlockEventStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		scope, start, end, ok := parseAnalyticsScope(w, r, sites)
		if !ok {
			return
		}
		limit := 50
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		rows, err := events.ListRecent(r.Context(), start, end, scope, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load recent L7 blocks")
			return
		}
		if rows == nil {
			rows = []store.L7BlockEventRow{}
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

func securityAnalyticsTopAttackIPsHandler(events store.L7BlockEventStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		scope, start, end, ok := parseAnalyticsScope(w, r, sites)
		if !ok {
			return
		}
		limit := 20
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		rows, err := events.ListTopIPs(r.Context(), start, end, scope, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load top L7 attacking IPs")
			return
		}
		if rows == nil {
			rows = []store.L7TopIPRow{}
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

func securityAnalyticsTopAttackURLsHandler(events store.L7BlockEventStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		scope, start, end, ok := parseAnalyticsScope(w, r, sites)
		if !ok {
			return
		}
		limit := 20
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		rows, err := events.ListTopURLs(r.Context(), start, end, scope, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load top L7 attacked URLs")
			return
		}
		if rows == nil {
			rows = []store.L7TopURLRow{}
		}
		writeJSON(w, http.StatusOK, rows)
	}
}
