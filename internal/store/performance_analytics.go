package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type PerformanceSummary struct {
	Requests            int64   `json:"requests"`
	EdgeResponseP50Ms   float64 `json:"edgeResponseP50Ms"`
	EdgeResponseP95Ms   float64 `json:"edgeResponseP95Ms"`
	EdgeResponseP99Ms   float64 `json:"edgeResponseP99Ms"`
	OriginResponseP50Ms float64 `json:"originResponseP50Ms"`
	OriginResponseP95Ms float64 `json:"originResponseP95Ms"`
	OriginRequests      int64   `json:"originRequests"`
	Origin5xx           int64   `json:"origin5xx"`
	OriginTimeouts      int64   `json:"originTimeouts"`
	OriginErrorRate     float64 `json:"originErrorRate"`
}

type PerformanceLatencyPoint struct {
	Timestamp string  `json:"timestamp"`
	P50       float64 `json:"p50"`
	P95       float64 `json:"p95"`
	P99       float64 `json:"p99"`
}

type PerformanceOriginStatusPoint struct {
	Timestamp string `json:"timestamp"`
	S2xx      int64  `json:"s2xx"`
	S3xx      int64  `json:"s3xx"`
	S4xx      int64  `json:"s4xx"`
	S5xx      int64  `json:"s5xx"`
	Timeouts  int64  `json:"timeouts"`
}

type PerformanceEdgeRow struct {
	ServerID  int64   `json:"serverId"`
	Name      string  `json:"name"`
	Requests  int64   `json:"requests"`
	P50Ms     float64 `json:"p50Ms"`
	P95Ms     float64 `json:"p95Ms"`
	ErrorRate float64 `json:"errorRate"`
}

type PerformanceOriginRow struct {
	SiteID    int64   `json:"siteId"`
	Domain    string  `json:"domain"`
	Requests  int64   `json:"requests"`
	P50Ms     float64 `json:"p50Ms"`
	P95Ms     float64 `json:"p95Ms"`
	ErrorRate float64 `json:"errorRate"`
	Timeouts  int64   `json:"timeouts"`
}

type SitePerformanceRow struct {
	SiteID             int64
	RequestCount       int64
	OriginRequestCount int64
	OriginCode2xx      int64
	OriginCode3xx      int64
	OriginCode4xx      int64
	OriginCode5xx      int64
	OriginTimeoutCount int64
	OriginErrorCount   int64
	EdgeLatencyHist    LatencyHist
	EdgeLatencySumMs   float64
	OriginLatencyHist  LatencyHist
	OriginLatencySumMs float64
}

func (store *serverTrafficStatsStore) ReplaceSitePerformanceBucket(ctx context.Context, serverID int64, bucket time.Time, rows []SitePerformanceRow) error {
	if serverID <= 0 {
		return fmt.Errorf("invalid server id")
	}
	bucket = bucket.UTC().Truncate(time.Minute)
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM site_performance_stats WHERE server_id = ? AND bucket_ts = ?`,
		serverID, bucket,
	); err != nil {
		return fmt.Errorf("clear site_performance_stats: %w", err)
	}
	if len(rows) == 0 {
		return tx.Commit()
	}

	placeholders := make([]string, 0, len(rows))
	args := make([]any, 0, len(rows)*15)
	for _, row := range rows {
		if row.SiteID <= 0 {
			continue
		}
		edgeJSON, err := json.Marshal(row.EdgeLatencyHist)
		if err != nil {
			return err
		}
		originJSON, err := json.Marshal(row.OriginLatencyHist)
		if err != nil {
			return err
		}
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		args = append(args,
			serverID,
			row.SiteID,
			bucket,
			row.RequestCount,
			row.OriginRequestCount,
			row.OriginCode2xx,
			row.OriginCode3xx,
			row.OriginCode4xx,
			row.OriginCode5xx,
			row.OriginTimeoutCount,
			row.OriginErrorCount,
			string(edgeJSON),
			row.EdgeLatencySumMs,
			string(originJSON),
			row.OriginLatencySumMs,
		)
	}
	if len(placeholders) == 0 {
		return tx.Commit()
	}
	query := `
		INSERT INTO site_performance_stats (
			server_id, site_id, bucket_ts, request_count, origin_request_count,
			origin_code2xx, origin_code3xx, origin_code4xx, origin_code5xx,
			origin_timeout_count, origin_error_count,
			edge_latency_hist, edge_latency_sum_ms, origin_latency_hist, origin_latency_sum_ms
		) VALUES ` + strings.Join(placeholders, ",")
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("insert site_performance_stats: %w", err)
	}
	return tx.Commit()
}

func scanLatencyHist(raw []byte) (LatencyHist, error) {
	var hist LatencyHist
	if len(raw) == 0 {
		return hist, nil
	}
	if err := json.Unmarshal(raw, &hist); err != nil {
		return hist, err
	}
	return hist, nil
}

func (store *serverTrafficStatsStore) SumPerformanceSummary(ctx context.Context, start, end time.Time, scope TrafficScope) (PerformanceSummary, error) {
	query := `
		SELECT
			COALESCE(SUM(request_count), 0),
			COALESCE(SUM(origin_request_count), 0),
			COALESCE(SUM(origin_code5xx), 0),
			COALESCE(SUM(origin_timeout_count), 0)
		FROM site_performance_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendTrafficScope(query, args, scope, true)

	var summary PerformanceSummary
	if err := store.db.QueryRowContext(ctx, query, args...).Scan(
		&summary.Requests,
		&summary.OriginRequests,
		&summary.Origin5xx,
		&summary.OriginTimeouts,
	); err != nil {
		return PerformanceSummary{}, err
	}
	edgeHist, err := store.mergeLatencyHist(ctx, start, end, scope, "edge_latency_hist")
	if err != nil {
		return PerformanceSummary{}, err
	}
	originHist, err := store.mergeLatencyHist(ctx, start, end, scope, "origin_latency_hist")
	if err != nil {
		return PerformanceSummary{}, err
	}
	summary.EdgeResponseP50Ms = round1f(edgeHist.Percentile(50))
	summary.EdgeResponseP95Ms = round1f(edgeHist.Percentile(95))
	summary.EdgeResponseP99Ms = round1f(edgeHist.Percentile(99))
	summary.OriginResponseP50Ms = round1f(originHist.Percentile(50))
	summary.OriginResponseP95Ms = round1f(originHist.Percentile(95))
	if summary.OriginRequests > 0 {
		summary.OriginErrorRate = round1f(float64(summary.Origin5xx) * 100 / float64(summary.OriginRequests))
	}
	return summary, nil
}

func (store *serverTrafficStatsStore) mergeLatencyHist(ctx context.Context, start, end time.Time, scope TrafficScope, column string) (LatencyHist, error) {
	if column != "edge_latency_hist" && column != "origin_latency_hist" {
		return LatencyHist{}, fmt.Errorf("invalid hist column")
	}
	query := `
		SELECT ` + column + `
		FROM site_performance_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendTrafficScope(query, args, scope, true)
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return LatencyHist{}, err
	}
	defer rows.Close()

	var merged LatencyHist
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return LatencyHist{}, err
		}
		hist, err := scanLatencyHist(raw)
		if err != nil {
			return LatencyHist{}, err
		}
		merged.Add(hist)
	}
	return merged, rows.Err()
}

// ListPerformanceLatencySeries merges histograms per chart bucket so percentiles
// stay true percentiles on long ranges. Buckets with no samples are omitted.
func (store *serverTrafficStatsStore) ListPerformanceLatencySeries(ctx context.Context, start, end time.Time, scope TrafficScope, kind string, bucketSize time.Duration) ([]PerformanceLatencyPoint, error) {
	if bucketSize < time.Minute {
		bucketSize = time.Minute
	}
	aligned := start.UTC().Truncate(bucketSize)
	column := "edge_latency_hist"
	if kind == "origin" {
		column = "origin_latency_hist"
	}
	query := `
		SELECT bucket_ts, ` + column + `
		FROM site_performance_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendTrafficScope(query, args, scope, true)
	query += ` ORDER BY bucket_ts`

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type acc struct {
		hist LatencyHist
	}
	order := make([]time.Time, 0)
	buckets := make(map[int64]*acc)
	for rows.Next() {
		var bucket time.Time
		var raw []byte
		if err := rows.Scan(&bucket, &raw); err != nil {
			return nil, err
		}
		hist, err := scanLatencyHist(raw)
		if err != nil {
			return nil, err
		}
		slot := bucket.UTC()
		if !slot.Before(aligned) {
			slot = aligned.Add(slot.Sub(aligned) / bucketSize * bucketSize)
		}
		key := slot.Unix()
		entry, ok := buckets[key]
		if !ok {
			entry = &acc{}
			buckets[key] = entry
			order = append(order, slot)
		}
		entry.hist.Add(hist)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]PerformanceLatencyPoint, 0, len(order))
	for _, bucket := range order {
		hist := buckets[bucket.Unix()].hist
		if hist.Sum() == 0 {
			continue
		}
		point := PerformanceLatencyPoint{
			Timestamp: bucket.Format(time.RFC3339),
			P50:       round1f(hist.Percentile(50)),
			P95:       round1f(hist.Percentile(95)),
		}
		if kind != "origin" {
			point.P99 = round1f(hist.Percentile(99))
		}
		out = append(out, point)
	}
	return out, nil
}

func (store *serverTrafficStatsStore) ListPerformanceOriginStatusSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]PerformanceOriginStatusPoint, error) {
	query := `
		SELECT bucket_ts,
		       COALESCE(SUM(origin_code2xx), 0),
		       COALESCE(SUM(origin_code3xx), 0),
		       COALESCE(SUM(origin_code4xx), 0),
		       COALESCE(SUM(origin_code5xx), 0),
		       COALESCE(SUM(origin_timeout_count), 0)
		FROM site_performance_stats
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

	var out []PerformanceOriginStatusPoint
	for rows.Next() {
		var bucket time.Time
		var point PerformanceOriginStatusPoint
		if err := rows.Scan(&bucket, &point.S2xx, &point.S3xx, &point.S4xx, &point.S5xx, &point.Timeouts); err != nil {
			return nil, err
		}
		point.Timestamp = bucket.Format(time.RFC3339)
		out = append(out, point)
	}
	return out, rows.Err()
}

func (store *serverTrafficStatsStore) ListPerformanceByEdge(ctx context.Context, start, end time.Time, scope TrafficScope) ([]PerformanceEdgeRow, error) {
	query := `
		SELECT p.server_id,
		       COALESCE(MAX(s.name), CONCAT('edge-', p.server_id)) AS name,
		       COALESCE(SUM(p.request_count), 0) AS requests,
		       COALESCE(SUM(p.origin_request_count), 0) AS origin_requests,
		       COALESCE(SUM(p.origin_code5xx), 0) AS origin_5xx
		FROM site_performance_stats p
		LEFT JOIN servers s ON s.id = p.server_id
		WHERE p.bucket_ts >= ? AND p.bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScopePrefixed(query, args, scope, "p")
	if scope.SiteID > 0 {
		query += ` AND p.site_id = ?`
		args = append(args, scope.SiteID)
	}
	query += `
		GROUP BY p.server_id
		HAVING requests > 0
		ORDER BY requests DESC`

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type edgeMeta struct {
		name           string
		requests       int64
		originRequests int64
		origin5xx      int64
	}
	metas := make(map[int64]edgeMeta)
	order := make([]int64, 0)
	for rows.Next() {
		var serverID, requests, originRequests, origin5xx int64
		var name string
		if err := rows.Scan(&serverID, &name, &requests, &originRequests, &origin5xx); err != nil {
			return nil, err
		}
		metas[serverID] = edgeMeta{name: name, requests: requests, originRequests: originRequests, origin5xx: origin5xx}
		order = append(order, serverID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]PerformanceEdgeRow, 0, len(order))
	for _, serverID := range order {
		meta := metas[serverID]
		edgeScope := TrafficScope{ServerID: serverID, SiteID: scope.SiteID, Restricted: true, ServerIDs: []int64{serverID}}
		hist, err := store.mergeLatencyHist(ctx, start, end, edgeScope, "edge_latency_hist")
		if err != nil {
			return nil, err
		}
		errorRate := 0.0
		if meta.originRequests > 0 {
			errorRate = float64(meta.origin5xx) * 100 / float64(meta.originRequests)
		}
		out = append(out, PerformanceEdgeRow{
			ServerID:  serverID,
			Name:      meta.name,
			Requests:  meta.requests,
			P50Ms:     round1f(hist.Percentile(50)),
			P95Ms:     round1f(hist.Percentile(95)),
			ErrorRate: round1f(errorRate),
		})
	}
	return out, nil
}

func (store *serverTrafficStatsStore) ListPerformanceByOrigin(ctx context.Context, start, end time.Time, scope TrafficScope) ([]PerformanceOriginRow, error) {
	query := `
		SELECT p.site_id,
		       COALESCE(MAX(s.domain), CONCAT('site-', p.site_id)) AS domain,
		       COALESCE(SUM(p.origin_request_count), 0) AS origin_requests,
		       COALESCE(SUM(p.origin_code5xx), 0) AS origin_5xx,
		       COALESCE(SUM(p.origin_timeout_count), 0) AS timeouts
		FROM site_performance_stats p
		LEFT JOIN sites s ON s.id = p.site_id
		WHERE p.bucket_ts >= ? AND p.bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScopePrefixed(query, args, scope, "p")
	if scope.SiteID > 0 {
		query += ` AND p.site_id = ?`
		args = append(args, scope.SiteID)
	}
	query += `
		GROUP BY p.site_id
		HAVING origin_requests > 0
		ORDER BY origin_requests DESC
		LIMIT 100`

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type siteMeta struct {
		domain         string
		originRequests int64
		origin5xx      int64
		timeouts       int64
	}
	metas := make(map[int64]siteMeta)
	order := make([]int64, 0)
	for rows.Next() {
		var siteID, originRequests, origin5xx, timeouts int64
		var domain string
		if err := rows.Scan(&siteID, &domain, &originRequests, &origin5xx, &timeouts); err != nil {
			return nil, err
		}
		metas[siteID] = siteMeta{domain: domain, originRequests: originRequests, origin5xx: origin5xx, timeouts: timeouts}
		order = append(order, siteID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]PerformanceOriginRow, 0, len(order))
	for _, siteID := range order {
		meta := metas[siteID]
		siteScope := scope
		siteScope.SiteID = siteID
		hist, err := store.mergeLatencyHist(ctx, start, end, siteScope, "origin_latency_hist")
		if err != nil {
			return nil, err
		}
		errorRate := 0.0
		if meta.originRequests > 0 {
			errorRate = float64(meta.origin5xx) * 100 / float64(meta.originRequests)
		}
		out = append(out, PerformanceOriginRow{
			SiteID:    siteID,
			Domain:    meta.domain,
			Requests:  meta.originRequests,
			P50Ms:     round1f(hist.Percentile(50)),
			P95Ms:     round1f(hist.Percentile(95)),
			ErrorRate: round1f(errorRate),
			Timeouts:  meta.timeouts,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].P95Ms == out[j].P95Ms {
			return out[i].Requests > out[j].Requests
		}
		return out[i].P95Ms > out[j].P95Ms
	})
	return out, nil
}
