package api

import (
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

func coarsenCacheStatusSeries(points []store.CacheStatusPoint, start, end time.Time) []store.CacheStatusPoint {
	return coarsenAnalyticsSeries(points, start, end, seriesAggSum,
		func(p store.CacheStatusPoint) string { return p.Timestamp },
		func(p store.CacheStatusPoint) []int64 {
			return []int64{p.Hit, p.Miss, p.Expired, p.Stale, p.Updating, p.Revalidated, p.Bypass, p.Dynamic}
		},
		func(ts string, v []int64) store.CacheStatusPoint {
			return store.CacheStatusPoint{
				Timestamp:   ts,
				Hit:         v[0],
				Miss:        v[1],
				Expired:     v[2],
				Stale:       v[3],
				Updating:    v[4],
				Revalidated: v[5],
				Bypass:      v[6],
				Dynamic:     v[7],
			}
		},
	)
}

func coarsenCacheBandwidthSeries(points []store.CacheBandwidthPoint, start, end time.Time) []store.CacheBandwidthPoint {
	return coarsenAnalyticsSeries(points, start, end, seriesAggSum,
		func(p store.CacheBandwidthPoint) string { return p.Timestamp },
		func(p store.CacheBandwidthPoint) []int64 { return []int64{p.CachedBytes, p.UncachedBytes} },
		func(ts string, v []int64) store.CacheBandwidthPoint {
			return store.CacheBandwidthPoint{Timestamp: ts, CachedBytes: v[0], UncachedBytes: v[1]}
		},
	)
}

func cacheAnalyticsSummaryHandler(stats store.ServerTrafficStatsStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		scope, start, end, ok := parseAnalyticsScope(w, r, sites)
		if !ok {
			return
		}
		summary, err := stats.SumCacheSummary(r.Context(), start, end, scope)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load cache summary")
			return
		}
		writeJSON(w, http.StatusOK, summary)
	}
}

func cacheAnalyticsSeriesHandler(stats store.ServerTrafficStatsStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		metric := strings.TrimPrefix(r.URL.Path, "/analytics/cache/series/")
		if metric == r.URL.Path {
			metric = strings.TrimPrefix(r.URL.Path, "/api/v1/analytics/cache/series/")
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
		case "status":
			points, err := stats.ListCacheStatusSeries(r.Context(), start, end, scope)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load cache status series")
				return
			}
			writeJSON(w, http.StatusOK, coarsenCacheStatusSeries(points, start, end))
		case "bandwidth":
			points, err := stats.ListCacheBandwidthSeries(r.Context(), start, end, scope)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load cache bandwidth series")
				return
			}
			writeJSON(w, http.StatusOK, coarsenCacheBandwidthSeries(points, start, end))
		default:
			writeError(w, http.StatusNotFound, "not found")
		}
	}
}

func cacheAnalyticsGroupHandler(stats store.ServerTrafficStatsStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		group := strings.TrimPrefix(r.URL.Path, "/analytics/cache/summary/")
		if group == r.URL.Path {
			group = strings.TrimPrefix(r.URL.Path, "/api/v1/analytics/cache/summary/")
		}
		group = strings.Trim(group, "/")
		// Exact /analytics/cache/summary is handled by cacheAnalyticsSummaryHandler.
		if group == "" || strings.Contains(group, "/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}

		scope, start, end, ok := parseAnalyticsScope(w, r, sites)
		if !ok {
			return
		}

		switch group {
		case "status":
			rows, err := stats.ListCacheStatusSummary(r.Context(), start, end, scope)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load cache status summary")
				return
			}
			writeJSON(w, http.StatusOK, rows)
		case "sites":
			rows, err := stats.ListCacheBySite(r.Context(), start, end, scope)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load cache by site")
				return
			}
			writeJSON(w, http.StatusOK, rows)
		case "content-types":
			rows, err := stats.ListCacheContentTypes(r.Context(), start, end, scope)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load cache content types")
				return
			}
			if rows == nil {
				rows = []store.CacheContentTypeRow{}
			}
			writeJSON(w, http.StatusOK, rows)
		case "top-miss-urls":
			rows, err := stats.ListCacheTopMissURLs(r.Context(), start, end, scope, 10)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load cache top miss urls")
				return
			}
			if rows == nil {
				rows = []store.CacheMissURLRow{}
			}
			writeJSON(w, http.StatusOK, rows)
		default:
			writeError(w, http.StatusNotFound, "not found")
		}
	}
}
