package api

import (
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

func coarsenPerformanceOriginStatusSeries(points []store.PerformanceOriginStatusPoint, start, end time.Time) []store.PerformanceOriginStatusPoint {
	return coarsenAnalyticsSeries(points, start, end, seriesAggSum,
		func(p store.PerformanceOriginStatusPoint) string { return p.Timestamp },
		func(p store.PerformanceOriginStatusPoint) []int64 {
			return []int64{p.S2xx, p.S3xx, p.S4xx, p.S5xx, p.Timeouts}
		},
		func(ts string, v []int64) store.PerformanceOriginStatusPoint {
			return store.PerformanceOriginStatusPoint{
				Timestamp: ts,
				S2xx:      v[0],
				S3xx:      v[1],
				S4xx:      v[2],
				S5xx:      v[3],
				Timeouts:  v[4],
			}
		},
	)
}

func performanceAnalyticsSummaryHandler(stats store.ServerTrafficStatsStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		scope, start, end, ok := parseAnalyticsScope(w, r, sites)
		if !ok {
			return
		}
		summary, err := stats.SumPerformanceSummary(r.Context(), start, end, scope)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load performance summary")
			return
		}
		writeJSON(w, http.StatusOK, summary)
	}
}

func performanceAnalyticsSeriesHandler(stats store.ServerTrafficStatsStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		metric := strings.TrimPrefix(r.URL.Path, "/analytics/performance/series/")
		if metric == r.URL.Path {
			metric = strings.TrimPrefix(r.URL.Path, "/api/v1/analytics/performance/series/")
		}
		metric = strings.Trim(metric, "/")
		if metric == "" || strings.Contains(metric, "/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}

		scope, start, end, ok := parseAnalyticsScope(w, r, sites)
		if !ok {
			return
		}

		switch metric {
		case "edge-response":
			points, err := stats.ListPerformanceLatencySeries(r.Context(), start, end, scope, "edge", analyticsChartBucket(start, end))
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load edge latency series")
				return
			}
			writeJSON(w, http.StatusOK, points)
		case "origin-response":
			points, err := stats.ListPerformanceLatencySeries(r.Context(), start, end, scope, "origin", analyticsChartBucket(start, end))
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load origin latency series")
				return
			}
			writeJSON(w, http.StatusOK, points)
		case "origin-status":
			points, err := stats.ListPerformanceOriginStatusSeries(r.Context(), start, end, scope)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load origin status series")
				return
			}
			writeJSON(w, http.StatusOK, coarsenPerformanceOriginStatusSeries(points, start, end))
		default:
			writeError(w, http.StatusNotFound, "not found")
		}
	}
}

func performanceAnalyticsGroupHandler(stats store.ServerTrafficStatsStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		group := strings.TrimPrefix(r.URL.Path, "/analytics/performance/summary/")
		if group == r.URL.Path {
			group = strings.TrimPrefix(r.URL.Path, "/api/v1/analytics/performance/summary/")
		}
		group = strings.Trim(group, "/")
		if group == "" || strings.Contains(group, "/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}

		scope, start, end, ok := parseAnalyticsScope(w, r, sites)
		if !ok {
			return
		}

		switch group {
		case "edges":
			rows, err := stats.ListPerformanceByEdge(r.Context(), start, end, scope)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load performance by edge")
				return
			}
			if rows == nil {
				rows = []store.PerformanceEdgeRow{}
			}
			writeJSON(w, http.StatusOK, rows)
		case "origins":
			rows, err := stats.ListPerformanceByOrigin(r.Context(), start, end, scope)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load performance by origin")
				return
			}
			if rows == nil {
				rows = []store.PerformanceOriginRow{}
			}
			writeJSON(w, http.StatusOK, rows)
		default:
			writeError(w, http.StatusNotFound, "not found")
		}
	}
}
