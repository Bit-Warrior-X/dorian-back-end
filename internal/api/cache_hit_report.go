package api

import (
	"encoding/json"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

type cacheHitReportPayload struct {
	Token                    string                      `json:"token"`
	Command                  string                      `json:"command"`
	ReportedAt               flexibleInt64               `json:"reported_at"`
	Timestamp                flexibleInt64               `json:"timestamp"`
	IntervalSeconds          flexibleInt64               `json:"interval_seconds"`
	ContentTypes             []cacheHitContentTypeItem   `json:"content_types"`
	TopMissURLs              []cacheHitTopMissURLItem    `json:"top_miss_urls"`
	ContentTypeRequestStats  []cacheHitContentTypeItem   `json:"content_type_request_stats"`
	CacheMissURLStats        []cacheHitTopMissURLItem    `json:"cache_miss_url_stats"`
	ContentTypesCount        flexibleInt64               `json:"content_types_count"`
	TopMissURLsCount         flexibleInt64               `json:"top_miss_urls_count"`
}

type cacheHitContentTypeItem struct {
	SiteID             flexibleInt64 `json:"site_id"`
	ContentType        string        `json:"content_type"`
	RequestCount       flexibleInt64 `json:"request_count"`
	TrafficL7Tx        json.Number   `json:"traffic_l7_tx"`
	CachedRequestCount flexibleInt64 `json:"cached_request_count"`
	TrafficCachedTx    json.Number   `json:"traffic_cached_tx"`
}

type cacheHitTopMissURLItem struct {
	SiteID       flexibleInt64 `json:"site_id"`
	Domain       string        `json:"domain"`
	URL          string        `json:"url"`
	MissCount    flexibleInt64 `json:"miss_count"`
	RequestCount flexibleInt64 `json:"request_count"`
}

type cacheHitReportResult struct {
	Status            string `json:"status"`
	ServerID          int64  `json:"serverId"`
	BucketTS          string `json:"bucketTs"`
	ContentTypes      int    `json:"contentTypes"`
	TopMissURLs       int    `json:"topMissUrls"`
	ReportedAt        int64  `json:"reportedAt,omitempty"`
	IntervalSeconds   int    `json:"intervalSeconds,omitempty"`
}

func jsonNumberToInt64(n json.Number) int64 {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return v
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	if f < 0 {
		return 0
	}
	return int64(math.Round(f))
}

func reportCacheHitHandler(servers store.ServerStore, stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var payload cacheHitReportPayload
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&payload); err != nil {
			log.Printf("[api] report_cache_hit invalid JSON: %v", err)
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		payload.Token = strings.TrimSpace(payload.Token)
		if payload.Token == "" {
			payload.Token = extractBearerOrAPIKey(r)
		}
		payload.Command = strings.TrimSpace(payload.Command)
		if payload.Token == "" {
			writeError(w, http.StatusForbidden, "missing token")
			return
		}
		if payload.Command != "" && !strings.EqualFold(payload.Command, "report_cache_hit") {
			writeError(w, http.StatusBadRequest, "unsupported command")
			return
		}

		server, err := servers.GetByToken(r.Context(), payload.Token)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusForbidden, "invalid token")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to validate token")
			return
		}

		ts := payload.Timestamp.Int64()
		if ts <= 0 {
			writeError(w, http.StatusBadRequest, "missing timestamp")
			return
		}
		interval := int(payload.IntervalSeconds.Int64())
		if interval <= 0 {
			interval = 60
		}

		contentTypes := payload.ContentTypes
		if len(contentTypes) == 0 {
			contentTypes = payload.ContentTypeRequestStats
		}
		missURLs := payload.TopMissURLs
		if len(missURLs) == 0 {
			missURLs = payload.CacheMissURLStats
		}

		input := store.CacheHitReportInput{
			BucketTS:     time.Unix(ts, 0).UTC(),
			IntervalSecs: interval,
			ContentTypes: make([]store.CacheHitContentTypeRow, 0, len(contentTypes)),
			TopMissURLs:  make([]store.CacheHitMissURLRow, 0, len(missURLs)),
		}
		for _, row := range contentTypes {
			ct := strings.TrimSpace(row.ContentType)
			if ct == "" {
				continue
			}
			input.ContentTypes = append(input.ContentTypes, store.CacheHitContentTypeRow{
				SiteID:             row.SiteID.Int64(),
				ContentType:        ct,
				RequestCount:       row.RequestCount.Int64(),
				TrafficL7Tx:        jsonNumberToInt64(row.TrafficL7Tx),
				CachedRequestCount: row.CachedRequestCount.Int64(),
				TrafficCachedTx:    jsonNumberToInt64(row.TrafficCachedTx),
			})
		}
		for _, row := range missURLs {
			url := strings.TrimSpace(row.URL)
			if url == "" {
				continue
			}
			input.TopMissURLs = append(input.TopMissURLs, store.CacheHitMissURLRow{
				SiteID:       row.SiteID.Int64(),
				Domain:       strings.TrimSpace(row.Domain),
				URL:          url,
				MissCount:    row.MissCount.Int64(),
				RequestCount: row.RequestCount.Int64(),
			})
		}

		if err := stats.ReplaceCacheHitReport(r.Context(), server.ID, input); err != nil {
			log.Printf("[api] report_cache_hit serverID=%d persist failed: %v", server.ID, err)
			writeError(w, http.StatusInternalServerError, "failed to store cache hit report")
			return
		}

		log.Printf(
			"[api] report_cache_hit ok serverID=%d bucket=%s contentTypes=%d topMiss=%d",
			server.ID,
			input.BucketTS.Format(time.RFC3339),
			len(input.ContentTypes),
			len(input.TopMissURLs),
		)
		writeJSON(w, http.StatusOK, cacheHitReportResult{
			Status:          "success",
			ServerID:        server.ID,
			BucketTS:        input.BucketTS.Format(time.RFC3339),
			ContentTypes:    len(input.ContentTypes),
			TopMissURLs:     len(input.TopMissURLs),
			ReportedAt:      payload.ReportedAt.Int64(),
			IntervalSeconds: interval,
		})
	}
}
