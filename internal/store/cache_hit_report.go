package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// CacheHitContentTypeRow is one Athens content-type family for a closed bucket.
type CacheHitContentTypeRow struct {
	SiteID             int64
	ContentType        string
	RequestCount       int64
	TrafficL7Tx        int64
	CachedRequestCount int64
	TrafficCachedTx    int64
}

// CacheHitMissURLRow is one top-missed URL for a closed bucket.
type CacheHitMissURLRow struct {
	SiteID       int64
	Domain       string
	URL          string
	MissCount    int64
	RequestCount int64
}

// CacheHitReportInput is one Angelos report_cache_hit bucket.
type CacheHitReportInput struct {
	BucketTS      time.Time
	IntervalSecs  int
	ContentTypes  []CacheHitContentTypeRow
	TopMissURLs   []CacheHitMissURLRow
}

func normalizeContentTypeFamily(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "html", "css", "js", "javascript", "json", "image", "video", "audio", "font", "document", "binary", "other":
		if strings.EqualFold(value, "javascript") {
			return "js"
		}
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "other"
	}
}

// contentTypeForAPI maps stored Athens families onto Cache analytics FE labels.
func contentTypeForAPI(value string) string {
	switch normalizeContentTypeFamily(value) {
	case "js":
		return "javascript"
	default:
		return normalizeContentTypeFamily(value)
	}
}

func (store *serverTrafficStatsStore) ReplaceCacheHitReport(ctx context.Context, serverID int64, input CacheHitReportInput) error {
	if serverID <= 0 {
		return fmt.Errorf("invalid server id")
	}
	bucket := input.BucketTS.UTC().Truncate(time.Minute)
	if bucket.IsZero() {
		return fmt.Errorf("invalid bucket timestamp")
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM content_type_request_stats WHERE server_id = ? AND bucket_ts = ?`,
		serverID, bucket,
	); err != nil {
		return fmt.Errorf("clear content_type_request_stats: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM cache_miss_url_stats WHERE server_id = ? AND bucket_ts = ?`,
		serverID, bucket,
	); err != nil {
		return fmt.Errorf("clear cache_miss_url_stats: %w", err)
	}

	if len(input.ContentTypes) > 0 {
		placeholders := make([]string, 0, len(input.ContentTypes))
		args := make([]any, 0, len(input.ContentTypes)*8)
		for _, row := range input.ContentTypes {
			ct := normalizeContentTypeFamily(row.ContentType)
			if row.RequestCount < 0 {
				row.RequestCount = 0
			}
			if row.CachedRequestCount < 0 {
				row.CachedRequestCount = 0
			}
			if row.CachedRequestCount > row.RequestCount {
				row.CachedRequestCount = row.RequestCount
			}
			if row.TrafficL7Tx < 0 {
				row.TrafficL7Tx = 0
			}
			if row.TrafficCachedTx < 0 {
				row.TrafficCachedTx = 0
			}
			if row.TrafficCachedTx > row.TrafficL7Tx {
				row.TrafficCachedTx = row.TrafficL7Tx
			}
			placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?, ?, ?)")
			args = append(args,
				serverID,
				row.SiteID,
				bucket,
				ct,
				row.RequestCount,
				row.TrafficL7Tx,
				row.CachedRequestCount,
				row.TrafficCachedTx,
			)
		}
		query := `
			INSERT INTO content_type_request_stats (
				server_id, site_id, bucket_ts, content_type,
				request_count, traffic_l7_tx, cached_request_count, traffic_cached_tx
			) VALUES ` + strings.Join(placeholders, ",")
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("insert content_type_request_stats: %w", err)
		}
	}

	if len(input.TopMissURLs) > 0 {
		placeholders := make([]string, 0, len(input.TopMissURLs))
		args := make([]any, 0, len(input.TopMissURLs)*9)
		for _, row := range input.TopMissURLs {
			domain := strings.ToLower(strings.TrimSpace(row.Domain))
			url := strings.TrimSpace(row.URL)
			if url == "" {
				continue
			}
			if row.MissCount < 0 {
				row.MissCount = 0
			}
			if row.RequestCount < 0 {
				row.RequestCount = 0
			}
			if row.MissCount > row.RequestCount && row.RequestCount > 0 {
				row.MissCount = row.RequestCount
			}
			if row.RequestCount == 0 && row.MissCount > 0 {
				row.RequestCount = row.MissCount
			}
			placeholders = append(placeholders, "(?, ?, ?, UNHEX(MD5(CONCAT(?, CHAR(0), ?))), ?, ?, ?, ?)")
			args = append(args,
				serverID,
				row.SiteID,
				bucket,
				domain, url,
				domain,
				url,
				row.MissCount,
				row.RequestCount,
			)
		}
		if len(placeholders) > 0 {
			query := `
				INSERT INTO cache_miss_url_stats (
					server_id, site_id, bucket_ts, url_hash, domain, request_url, miss_count, request_count
				) VALUES ` + strings.Join(placeholders, ",")
			if _, err := tx.ExecContext(ctx, query, args...); err != nil {
				return fmt.Errorf("insert cache_miss_url_stats: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (store *serverTrafficStatsStore) ListCacheContentTypes(ctx context.Context, start, end time.Time, scope TrafficScope) ([]CacheContentTypeRow, error) {
	query := `
		SELECT content_type,
		       COALESCE(SUM(request_count), 0) AS requests,
		       COALESCE(SUM(traffic_l7_tx), 0) AS bytes,
		       COALESCE(SUM(cached_request_count), 0) AS cached
		FROM content_type_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendTrafficScope(query, args, scope, true)
	query += `
		GROUP BY content_type
		HAVING requests > 0
		ORDER BY requests DESC`

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CacheContentTypeRow
	for rows.Next() {
		var contentType string
		var requests, bytes, cached int64
		if err := rows.Scan(&contentType, &requests, &bytes, &cached); err != nil {
			return nil, err
		}
		ratio := 0.0
		if requests > 0 {
			ratio = float64(cached) * 100 / float64(requests)
		}
		out = append(out, CacheContentTypeRow{
			ContentType: contentTypeForAPI(contentType),
			Requests:    requests,
			Bytes:       bytes,
			HitRatio:    round1(ratio),
		})
	}
	return out, rows.Err()
}

func (store *serverTrafficStatsStore) ListCacheTopMissURLs(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]CacheMissURLRow, error) {
	if limit <= 0 {
		limit = 10
	}
	query := `
		SELECT domain,
		       request_url,
		       COALESCE(SUM(miss_count), 0) AS misses,
		       COALESCE(SUM(request_count), 0) AS requests
		FROM cache_miss_url_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendTrafficScope(query, args, scope, true)
	query += `
		GROUP BY domain, request_url
		HAVING misses > 0
		ORDER BY misses DESC
		LIMIT ?`
	args = append(args, limit)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CacheMissURLRow
	for rows.Next() {
		var host, url string
		var misses, requests int64
		if err := rows.Scan(&host, &url, &misses, &requests); err != nil {
			return nil, err
		}
		ratio := 0.0
		if requests > 0 {
			hits := requests - misses
			if hits < 0 {
				hits = 0
			}
			ratio = float64(hits) * 100 / float64(requests)
		}
		out = append(out, CacheMissURLRow{
			Host:     host,
			URL:      url,
			Misses:   misses,
			Requests: requests,
			HitRatio: round1(ratio),
		})
	}
	return out, rows.Err()
}
