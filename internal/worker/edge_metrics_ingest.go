package worker

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

// EdgeMetricsItem is one closed Sparta/Athens bucket from report_edge_metrics.
type EdgeMetricsItem struct {
	Source           string          `json:"source"`
	Endpoint         string          `json:"endpoint"`
	EndpointAliases  []string        `json:"endpoint_aliases"`
	Timestamp        int64           `json:"timestamp"`
	IntervalSeconds  int64           `json:"interval_seconds"`
	Payload          json.RawMessage `json:"payload"`
}

// IngestEdgeMetricsItem stores one closed metrics bucket idempotently by
// (server_id, endpoint identity, timestamp). Unknown endpoints are skipped.
func IngestEdgeMetricsItem(ctx context.Context, dbConn *sql.DB, serverID int64, item EdgeMetricsItem) error {
	if dbConn == nil || serverID <= 0 {
		return fmt.Errorf("invalid metrics ingest identity")
	}
	endpoint := normalizeMetricsEndpoint(item.Endpoint, item.EndpointAliases)
	if endpoint == "" {
		return fmt.Errorf("missing endpoint")
	}
	ts := item.Timestamp
	payload := bytesOrEmpty(item.Payload)
	if ts <= 0 {
		ts = peekPayloadTimestamp(payload)
	}
	if ts <= 0 {
		return fmt.Errorf("missing timestamp for %s", endpoint)
	}
	bucket := time.Unix(ts, 0).UTC()

	switch endpoint {
	case "l4_traffic_stats", "l4_attack_stats":
		data, err := decodeL4AttackBucket(payload)
		if err != nil {
			return fmt.Errorf("decode l4_traffic_stats: %w", err)
		}
		if data.Timestamp <= 0 {
			data.Timestamp = ts
		}
		// Closed Angelos buckets default to 60s and currently post the SUM of
		// Sparta's 1s rates. Store average bytes/s so charts and attack peaks
		// match NIC (treating the sum as an instantaneous rate showed ~60× Gbps).
		interval := item.IntervalSeconds
		if interval <= 0 {
			interval = 60
		}
		averageL4StatsOverInterval(&data.Stats, interval)
		return insertL4AttackBucket(ctx, dbConn, serverID, bucket, data)

	case "server_traffic_stats":
		var data serverTrafficStatsPayload
		if err := json.Unmarshal(payload, &data); err != nil {
			return fmt.Errorf("decode server_traffic_stats: %w", err)
		}
		if data.Timestamp <= 0 {
			data.Timestamp = ts
		}
		return insertServerTrafficSnapshot(ctx, dbConn, serverID, bucket, data)

	case "site_traffic_stats":
		var data siteTrafficStatsBucketResponse
		if err := json.Unmarshal(payload, &data); err != nil {
			return fmt.Errorf("decode site_traffic_stats: %w", err)
		}
		if err := insertSiteTrafficBucket(ctx, dbConn, serverID, bucket, data); err != nil {
			return err
		}
		return insertSitePerformanceBucket(ctx, dbConn, serverID, bucket, data)

	case "ip_request_stats":
		var data ipRequestStatsBucketResponse
		if err := json.Unmarshal(payload, &data); err != nil {
			return fmt.Errorf("decode ip_request_stats: %w", err)
		}
		return insertIPRequestBucket(ctx, dbConn, serverID, bucket, data)

	case "url_request_stats":
		var data urlRequestStatsBucketResponse
		if err := json.Unmarshal(payload, &data); err != nil {
			return fmt.Errorf("decode url_request_stats: %w", err)
		}
		return insertURLRequestBucket(ctx, dbConn, serverID, bucket, data)

	case "useragent_request_stats":
		var data userAgentRequestStatsBucketResponse
		if err := json.Unmarshal(payload, &data); err != nil {
			return fmt.Errorf("decode useragent_request_stats: %w", err)
		}
		return insertUserAgentRequestBucket(ctx, dbConn, serverID, bucket, data)

	case "country_request_stats":
		var data countryRequestStatsBucketResponse
		if err := json.Unmarshal(payload, &data); err != nil {
			return fmt.Errorf("decode country_request_stats: %w", err)
		}
		return insertCountryRequestBucket(ctx, dbConn, serverID, bucket, data)

	case "isp_request_stats":
		var data ispRequestStatsBucketResponse
		if err := json.Unmarshal(payload, &data); err != nil {
			return fmt.Errorf("decode isp_request_stats: %w", err)
		}
		return insertISPRequestBucket(ctx, dbConn, serverID, bucket, data)

	case "referer_request_stats":
		var data refererRequestStatsBucketResponse
		if err := json.Unmarshal(payload, &data); err != nil {
			return fmt.Errorf("decode referer_request_stats: %w", err)
		}
		return insertRefererRequestBucket(ctx, dbConn, serverID, bucket, data)

	case "domain_request_stats":
		var data domainRequestStatsBucketResponse
		if err := json.Unmarshal(payload, &data); err != nil {
			return fmt.Errorf("decode domain_request_stats: %w", err)
		}
		return insertDomainRequestBucket(ctx, dbConn, serverID, bucket, data)

	case "block_reason_stats":
		var data blockReasonStatsBucketResponse
		if err := json.Unmarshal(payload, &data); err != nil {
			return fmt.Errorf("decode block_reason_stats: %w", err)
		}
		return insertBlockReasonBucket(ctx, dbConn, serverID, bucket, data)

	case "content_type_request_stats":
		return ingestContentTypeStats(ctx, dbConn, serverID, bucket, payload)

	case "cache_miss_url_stats":
		return ingestCacheMissURLStats(ctx, dbConn, serverID, bucket, payload)

	default:
		return fmt.Errorf("unsupported metrics endpoint %q", endpoint)
	}
}

func normalizeMetricsEndpoint(endpoint string, aliases []string) string {
	endpoint = strings.ToLower(strings.TrimSpace(endpoint))
	if endpoint != "" {
		return endpoint
	}
	for _, alias := range aliases {
		alias = strings.ToLower(strings.TrimSpace(alias))
		if alias != "" {
			return alias
		}
	}
	return ""
}

func bytesOrEmpty(raw json.RawMessage) []byte {
	if len(raw) == 0 || string(raw) == "null" {
		return []byte("{}")
	}
	return raw
}

func peekPayloadTimestamp(payload []byte) int64 {
	var probe struct {
		Timestamp int64 `json:"timestamp"`
	}
	_ = json.Unmarshal(payload, &probe)
	return probe.Timestamp
}

// averageL4StatsOverInterval converts interval totals (sum of 1s B/s samples)
// into an average bytes/s rate. intervalSeconds <= 1 leaves rates unchanged.
func averageL4StatsOverInterval(stats *l4AttackStatsInner, intervalSeconds int64) {
	if stats == nil || intervalSeconds <= 1 {
		return
	}
	div := intervalSeconds
	stats.Total /= div
	stats.Allow /= div
	stats.Block /= div
	stats.TCP /= div
	stats.UDP /= div
	stats.ICMP /= div
	stats.GRE /= div
	stats.Other /= div
	stats.Syn /= div
	stats.Ack /= div
	stats.Rst /= div
	stats.Stomp /= div
	stats.Psh /= div
}

func decodeL4AttackBucket(payload []byte) (l4AttackStatsBucketResponse, error) {
	var wrapper struct {
		Timestamp int64              `json:"timestamp"`
		Stats     l4AttackStatsInner `json:"stats"`
		Total     int64              `json:"total"`
		Allow     int64              `json:"allow"`
		Block     int64              `json:"block"`
		Syn       int64              `json:"syn"`
		Ack       int64              `json:"ack"`
		Rst       int64              `json:"rst"`
		TCP       int64              `json:"tcp"`
		UDP       int64              `json:"udp"`
		ICMP      int64              `json:"icmp"`
		GRE       int64              `json:"gre"`
		Other     int64              `json:"other"`
		Stomp     int64              `json:"stomp"`
		Psh       int64              `json:"psh"`
	}
	if err := json.Unmarshal(payload, &wrapper); err != nil {
		return l4AttackStatsBucketResponse{}, err
	}
	stats := wrapper.Stats
	if stats.Total == 0 && wrapper.Total != 0 {
		stats.Total = wrapper.Total
	}
	if stats.Allow == 0 && wrapper.Allow != 0 {
		stats.Allow = wrapper.Allow
	}
	if stats.Block == 0 && wrapper.Block != 0 {
		stats.Block = wrapper.Block
	}
	if stats.Syn == 0 && wrapper.Syn != 0 {
		stats.Syn = wrapper.Syn
	}
	if stats.Ack == 0 && wrapper.Ack != 0 {
		stats.Ack = wrapper.Ack
	}
	if stats.Rst == 0 && wrapper.Rst != 0 {
		stats.Rst = wrapper.Rst
	}
	if stats.TCP == 0 && wrapper.TCP != 0 {
		stats.TCP = wrapper.TCP
	}
	if stats.UDP == 0 && wrapper.UDP != 0 {
		stats.UDP = wrapper.UDP
	}
	if stats.ICMP == 0 && wrapper.ICMP != 0 {
		stats.ICMP = wrapper.ICMP
	}
	if stats.GRE == 0 && wrapper.GRE != 0 {
		stats.GRE = wrapper.GRE
	}
	if stats.Other == 0 && wrapper.Other != 0 {
		stats.Other = wrapper.Other
	}
	if stats.Stomp == 0 && wrapper.Stomp != 0 {
		stats.Stomp = wrapper.Stomp
	}
	if stats.Psh == 0 && wrapper.Psh != 0 {
		stats.Psh = wrapper.Psh
	}
	return l4AttackStatsBucketResponse{Timestamp: wrapper.Timestamp, Stats: stats}, nil
}

type contentTypeStatsPayload struct {
	Timestamp               int64 `json:"timestamp"`
	ContentTypeRequestStats []struct {
		SiteID             int64       `json:"site_id"`
		ContentType        string      `json:"content_type"`
		RequestCount       int64       `json:"request_count"`
		TrafficL7Tx        json.Number `json:"traffic_l7_tx"`
		CachedRequestCount int64       `json:"cached_request_count"`
		TrafficCachedTx    json.Number `json:"traffic_cached_tx"`
		CacheHitRatio      float64     `json:"cache_hit_ratio"`
	} `json:"content_type_request_stats"`
}

type cacheMissURLStatsPayload struct {
	Timestamp         int64 `json:"timestamp"`
	CacheMissURLStats []struct {
		SiteID       int64  `json:"site_id"`
		Domain       string `json:"domain"`
		URL          string `json:"url"`
		MissCount    int64  `json:"miss_count"`
		RequestCount int64  `json:"request_count"`
	} `json:"cache_miss_url_stats"`
}

func ingestContentTypeStats(ctx context.Context, dbConn *sql.DB, serverID int64, bucket time.Time, payload []byte) error {
	var data contentTypeStatsPayload
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("decode content_type_request_stats: %w", err)
	}
	rows := make([]store.CacheHitContentTypeRow, 0, len(data.ContentTypeRequestStats))
	for _, row := range data.ContentTypeRequestStats {
		ct := strings.TrimSpace(row.ContentType)
		if ct == "" {
			continue
		}
		rows = append(rows, store.CacheHitContentTypeRow{
			SiteID:             row.SiteID,
			ContentType:        ct,
			RequestCount:       row.RequestCount,
			TrafficL7Tx:        jsonNumberToInt64(row.TrafficL7Tx),
			CachedRequestCount: row.CachedRequestCount,
			TrafficCachedTx:    jsonNumberToInt64(row.TrafficCachedTx),
		})
	}
	return store.NewServerTrafficStatsStore(dbConn).ReplaceContentTypeBucket(ctx, serverID, bucket, rows)
}

func ingestCacheMissURLStats(ctx context.Context, dbConn *sql.DB, serverID int64, bucket time.Time, payload []byte) error {
	var data cacheMissURLStatsPayload
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("decode cache_miss_url_stats: %w", err)
	}
	rows := make([]store.CacheHitMissURLRow, 0, len(data.CacheMissURLStats))
	for _, row := range data.CacheMissURLStats {
		url := strings.TrimSpace(row.URL)
		if url == "" {
			continue
		}
		rows = append(rows, store.CacheHitMissURLRow{
			SiteID:       row.SiteID,
			Domain:       row.Domain,
			URL:          url,
			MissCount:    row.MissCount,
			RequestCount: row.RequestCount,
		})
	}
	return store.NewServerTrafficStatsStore(dbConn).ReplaceCacheMissURLBucket(ctx, serverID, bucket, rows)
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
