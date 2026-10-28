package store

import (
	"context"
	"time"
)

// CacheSummary matches Analytics → Cache FE summary payload.
type CacheSummary struct {
	Requests       int64 `json:"requests"`
	CachedRequests int64 `json:"cachedRequests"`
	Bytes          int64 `json:"bytes"`
	CachedBytes    int64 `json:"cachedBytes"`
	OriginRequests int64 `json:"originRequests"`
	OriginBytes    int64 `json:"originBytes"`
}

// CacheStatusPoint is a time-bucket of Athens cache counters (HIT / MISS / BYPASS).
// Other nginx cache statuses are not reported by the edge and stay zero for FE compat.
type CacheStatusPoint struct {
	Timestamp   string `json:"timestamp"`
	Hit         int64  `json:"hit"`
	Miss        int64  `json:"miss"`
	Expired     int64  `json:"expired"`
	Stale       int64  `json:"stale"`
	Updating    int64  `json:"updating"`
	Revalidated int64  `json:"revalidated"`
	Bypass      int64  `json:"bypass"`
	Dynamic     int64  `json:"dynamic"`
}

// CacheBandwidthPoint splits L7 TX bytes into served-from-cache vs origin/uncached.
type CacheBandwidthPoint struct {
	Timestamp     string `json:"timestamp"`
	CachedBytes   int64  `json:"cachedBytes"`
	UncachedBytes int64  `json:"uncachedBytes"`
}

// CacheStatusRow is an aggregate status breakdown for the status list.
type CacheStatusRow struct {
	Status   string `json:"status"`
	Requests int64  `json:"requests"`
	Bytes    int64  `json:"bytes"`
}

// CacheContentTypeRow is reserved for future mime/content-type breakdowns.
type CacheContentTypeRow struct {
	ContentType string  `json:"contentType"`
	Requests    int64   `json:"requests"`
	Bytes       int64   `json:"bytes"`
	HitRatio    float64 `json:"hitRatio"`
}

// CacheMissURLRow is reserved until per-URL cache counters exist.
type CacheMissURLRow struct {
	Host     string  `json:"host"`
	URL      string  `json:"url"`
	Misses   int64   `json:"misses"`
	Requests int64   `json:"requests"`
	HitRatio float64 `json:"hitRatio"`
}

// CacheSiteRow is per-site cache effectiveness over the window.
type CacheSiteRow struct {
	SiteID       int64   `json:"siteId"`
	Domain       string  `json:"domain"`
	Requests     int64   `json:"requests"`
	HitRatio     float64 `json:"hitRatio"`
	ByteHitRatio float64 `json:"byteHitRatio"`
	SavedBytes   int64   `json:"savedBytes"`
}

// cacheTxBytesExpr sums L7 egress in bytes; traffic_l7_tx is stored in KiB.
func cacheTxBytesExpr(prefix string) string {
	return "COALESCE(CAST(SUM(" + prefix + "traffic_l7_tx) * 1024 AS SIGNED), 0)"
}

// splitCacheBytes apportions egress bytes by request status; Athens does not
// report per-status bytes, so this is a request-weighted estimate.
func splitCacheBytes(txBytes, hit, miss, bypass int64) (cached, uncached int64) {
	total := hit + miss + bypass
	if txBytes <= 0 || total <= 0 {
		return 0, max64(txBytes, 0)
	}
	cached = txBytes * hit / total
	uncached = txBytes - cached
	if uncached < 0 {
		uncached = 0
	}
	return cached, uncached
}

func hitRatioPercent(hit, miss int64) float64 {
	den := hit + miss
	if den <= 0 {
		return 0
	}
	return float64(hit) * 100 / float64(den)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (store *serverTrafficStatsStore) SumCacheSummary(ctx context.Context, start, end time.Time, scope TrafficScope) (CacheSummary, error) {
	query := `
		SELECT
			COALESCE(SUM(request_count), 0),
			COALESCE(SUM(cache_hit_count), 0),
			COALESCE(SUM(cache_miss_count), 0),
			COALESCE(SUM(cache_bypass_count), 0),
			` + cacheTxBytesExpr("") + `
		FROM site_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendTrafficScope(query, args, scope, true)

	var requests, hit, miss, bypass, txBytes int64
	if err := store.db.QueryRowContext(ctx, query, args...).Scan(&requests, &hit, &miss, &bypass, &txBytes); err != nil {
		return CacheSummary{}, err
	}
	cachedBytes, originBytes := splitCacheBytes(txBytes, hit, miss, bypass)
	originRequests := miss + bypass
	if requests < hit+originRequests {
		requests = hit + originRequests
	}
	return CacheSummary{
		Requests:       requests,
		CachedRequests: hit,
		Bytes:          txBytes,
		CachedBytes:    cachedBytes,
		OriginRequests: originRequests,
		OriginBytes:    originBytes,
	}, nil
}

func (store *serverTrafficStatsStore) ListCacheStatusSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]CacheStatusPoint, error) {
	query := `
		SELECT bucket_ts,
		       COALESCE(SUM(cache_hit_count), 0),
		       COALESCE(SUM(cache_miss_count), 0),
		       COALESCE(SUM(cache_bypass_count), 0)
		FROM site_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendTrafficScope(query, args, scope, true)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts`

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []CacheStatusPoint
	for rows.Next() {
		var bucket time.Time
		var point CacheStatusPoint
		if err := rows.Scan(&bucket, &point.Hit, &point.Miss, &point.Bypass); err != nil {
			return nil, err
		}
		point.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, point)
	}
	return points, rows.Err()
}

func (store *serverTrafficStatsStore) ListCacheBandwidthSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]CacheBandwidthPoint, error) {
	query := `
		SELECT bucket_ts,
		       COALESCE(SUM(cache_hit_count), 0),
		       COALESCE(SUM(cache_miss_count), 0),
		       COALESCE(SUM(cache_bypass_count), 0),
		       ` + cacheTxBytesExpr("") + `
		FROM site_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendTrafficScope(query, args, scope, true)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts`

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []CacheBandwidthPoint
	for rows.Next() {
		var bucket time.Time
		var hit, miss, bypass, txBytes int64
		if err := rows.Scan(&bucket, &hit, &miss, &bypass, &txBytes); err != nil {
			return nil, err
		}
		cached, uncached := splitCacheBytes(txBytes, hit, miss, bypass)
		points = append(points, CacheBandwidthPoint{
			Timestamp:     bucket.Format(time.RFC3339),
			CachedBytes:   cached,
			UncachedBytes: uncached,
		})
	}
	return points, rows.Err()
}

func (store *serverTrafficStatsStore) ListCacheStatusSummary(ctx context.Context, start, end time.Time, scope TrafficScope) ([]CacheStatusRow, error) {
	summary, err := store.SumCacheSummary(ctx, start, end, scope)
	if err != nil {
		return nil, err
	}
	hit := summary.CachedRequests
	miss := int64(0)
	bypass := int64(0)
	// Re-query miss/bypass precisely (summary folds them into OriginRequests).
	query := `
		SELECT
			COALESCE(SUM(cache_miss_count), 0),
			COALESCE(SUM(cache_bypass_count), 0)
		FROM site_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendTrafficScope(query, args, scope, true)
	if err := store.db.QueryRowContext(ctx, query, args...).Scan(&miss, &bypass); err != nil {
		return nil, err
	}

	rows := make([]CacheStatusRow, 0, 3)
	appendRow := func(status string, requests int64) {
		if requests <= 0 {
			return
		}
		bytes := int64(0)
		total := hit + miss + bypass
		if total > 0 && summary.Bytes > 0 {
			bytes = summary.Bytes * requests / total
		}
		rows = append(rows, CacheStatusRow{Status: status, Requests: requests, Bytes: bytes})
	}
	appendRow("HIT", hit)
	appendRow("MISS", miss)
	appendRow("BYPASS", bypass)
	return rows, nil
}

func (store *serverTrafficStatsStore) ListCacheBySite(ctx context.Context, start, end time.Time, scope TrafficScope) ([]CacheSiteRow, error) {
	query := `
		SELECT t.site_id,
		       COALESCE(MAX(s.domain), CONCAT('site-', t.site_id)) AS domain,
		       COALESCE(SUM(t.request_count), 0) AS requests,
		       COALESCE(SUM(t.cache_hit_count), 0) AS hit,
		       COALESCE(SUM(t.cache_miss_count), 0) AS miss,
		       COALESCE(SUM(t.cache_bypass_count), 0) AS bypass,
		       ` + cacheTxBytesExpr("t.") + ` AS tx_bytes
		FROM site_traffic_stats t
		LEFT JOIN sites s ON s.id = t.site_id
		WHERE t.bucket_ts >= ? AND t.bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScopePrefixed(query, args, scope, "t")
	if scope.SiteID > 0 {
		query += ` AND t.site_id = ?`
		args = append(args, scope.SiteID)
	}
	query += `
		GROUP BY t.site_id
		HAVING requests > 0 OR hit > 0 OR miss > 0 OR bypass > 0
		ORDER BY requests DESC
		LIMIT 100`

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CacheSiteRow
	for rows.Next() {
		var siteID, requests, hit, miss, bypass, txBytes int64
		var domain string
		if err := rows.Scan(&siteID, &domain, &requests, &hit, &miss, &bypass, &txBytes); err != nil {
			return nil, err
		}
		cachedBytes, _ := splitCacheBytes(txBytes, hit, miss, bypass)
		reqHitRatio := hitRatioPercent(hit, miss+bypass)
		byteHitRatio := 0.0
		if total := hit + miss + bypass; total > 0 && txBytes > 0 {
			byteHitRatio = float64(cachedBytes) * 100 / float64(txBytes)
		}
		if requests < hit+miss+bypass {
			requests = hit + miss + bypass
		}
		out = append(out, CacheSiteRow{
			SiteID:       siteID,
			Domain:       domain,
			Requests:     requests,
			HitRatio:     round1(reqHitRatio),
			ByteHitRatio: round1(byteHitRatio),
			SavedBytes:   cachedBytes,
		})
	}
	return out, rows.Err()
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}
