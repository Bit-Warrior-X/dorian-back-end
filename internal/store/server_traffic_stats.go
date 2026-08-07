package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type ServerBandwidthPoint struct {
	ServerID  int64  `json:"serverId"`
	Timestamp string `json:"timestamp"`
	Bandwidth int64  `json:"bandwidth"`
}

type RequestResponsePoint struct {
	Timestamp     string `json:"timestamp"`
	RequestCount  int64  `json:"requestCount"`
	ResponseCount int64  `json:"responseCount"`
}

type StatusCodePoint struct {
	Timestamp string `json:"timestamp"`
	Success   int64  `json:"success"`
	Redirect  int64  `json:"redirect"`
	Client    int64  `json:"client"`
	Server    int64  `json:"server"`
}

type TrafficPoint struct {
	Timestamp string `json:"timestamp"`
	Traffic   int64  `json:"traffic"`
}

type IpCountPoint struct {
	Timestamp string `json:"timestamp"`
	Count     int64  `json:"count"`
}

type MethodSeriesPoint struct {
	Timestamp    string `json:"timestamp"`
	GetCount     int64  `json:"getCount"`
	PostCount    int64  `json:"postCount"`
	DeleteCount  int64  `json:"deleteCount"`
	PutCount     int64  `json:"putCount"`
	HeadCount    int64  `json:"headCount"`
	PatchCount   int64  `json:"patchCount"`
	OptionsCount int64  `json:"optionsCount"`
	OthersCount  int64  `json:"othersCount"`
}

type ProtocolSeriesPoint struct {
	Timestamp string `json:"timestamp"`
	Http1_0   int64  `json:"http1_0"`
	Http1_1   int64  `json:"http1_1"`
	Http2     int64  `json:"http2"`
	Http3     int64  `json:"http3"`
}

type StatusCodeSummary struct {
	Code200 int64 `json:"code200"`
	Code206 int64 `json:"code206"`
	Code301 int64 `json:"code301"`
	Code302 int64 `json:"code302"`
	Code400 int64 `json:"code400"`
	Code403 int64 `json:"code403"`
	Code404 int64 `json:"code404"`
	Code444 int64 `json:"code444"`
	Code499 int64 `json:"code499"`
	Code500 int64 `json:"code500"`
	Code502 int64 `json:"code502"`
	Code503 int64 `json:"code503"`
	Code504 int64 `json:"code504"`
	Code904 int64 `json:"code904"`
	Code929 int64 `json:"code929"`
	Code978 int64 `json:"code978"`
}

type MethodSummary struct {
	GetCount     int64 `json:"getCount"`
	PostCount    int64 `json:"postCount"`
	DeleteCount  int64 `json:"deleteCount"`
	PutCount     int64 `json:"putCount"`
	HeadCount    int64 `json:"headCount"`
	PatchCount   int64 `json:"patchCount"`
	OptionsCount int64 `json:"optionsCount"`
	OthersCount  int64 `json:"othersCount"`
}

type ProtocolSummary struct {
	Http1_0 int64 `json:"http1_0"`
	Http1_1 int64 `json:"http1_1"`
	Http2   int64 `json:"http2"`
	Http3   int64 `json:"http3"`
}

type TopIPRow struct {
	IP       string `json:"ip"`
	Requests int64  `json:"requests"`
}

type TopIspRow struct {
	ISP      string `json:"isp"`
	Requests int64  `json:"requests"`
}

type TopRefererRow struct {
	Referer  string `json:"referer"`
	Requests int64  `json:"requests"`
}

type TopUrlRow struct {
	URL      string `json:"url"`
	Requests int64  `json:"requests"`
}

type TopUserAgentRow struct {
	Agent    string `json:"agent"`
	Requests int64  `json:"requests"`
}

type TopDomainRow struct {
	Domain    string  `json:"domain"`
	Requests  int64   `json:"requests"`
	Bandwidth uint64  `json:"bandwidth"`
	CacheHit  float64 `json:"cacheHit"`
	Status    string  `json:"status"`
}

type CountryRequestRow struct {
	CountryCode string `json:"countryCode"`
	Requests    int64  `json:"requests"`
	Blocked     int64  `json:"blocked"`
}

type BlockedRequestPoint struct {
	Timestamp string `json:"timestamp"`
	Count     int64  `json:"count"`
}

type ServerTrafficStatsStore interface {
	ListBandwidth(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ServerBandwidthPoint, error)
	ListNicRxBandwidthByServer(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ServerBandwidthPoint, error)
	ListNicTxBandwidthByServer(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ServerBandwidthPoint, error)
	ListL7RxBandwidthByServer(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ServerBandwidthPoint, error)
	ListL7TxBandwidthByServer(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ServerBandwidthPoint, error)
	ListNicRxBandwidthAggregate(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error)
	ListNicTxBandwidthAggregate(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error)
	ListL7RxBandwidthAggregate(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error)
	ListL7TxBandwidthAggregate(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error)
	ListRequestResponse(ctx context.Context, start, end time.Time, scope TrafficScope) ([]RequestResponsePoint, error)
	ListStatusCodes(ctx context.Context, start, end time.Time, scope TrafficScope) ([]StatusCodePoint, error)
	ListNicRxTraffic(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error)
	ListNicTxTraffic(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error)
	ListL7RxTraffic(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error)
	ListL7TxTraffic(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error)
	ListIpCount(ctx context.Context, start, end time.Time, scope TrafficScope) ([]IpCountPoint, error)
	ListBlockedRequestSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]BlockedRequestPoint, error)
	ListMethodSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]MethodSeriesPoint, error)
	ListProtocolSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ProtocolSeriesPoint, error)
	SumStatusCodes(ctx context.Context, start, end time.Time, scope TrafficScope) (StatusCodeSummary, error)
	SumMethods(ctx context.Context, start, end time.Time, scope TrafficScope) (MethodSummary, error)
	SumProtocols(ctx context.Context, start, end time.Time, scope TrafficScope) (ProtocolSummary, error)
	SumTotals(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, int64, int64, int64, int64, int64, error)
	SumSecurityTotals(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, int64, int64, int64, error)
	LatestNicRxBandwidth(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, time.Time, error)
	LatestNicTxBandwidth(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, time.Time, error)
	LatestL7RxBandwidth(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, time.Time, error)
	LatestL7TxBandwidth(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, time.Time, error)
	SumBlockedRequests(ctx context.Context, start, end time.Time) (int64, error)
	ListTopIPs(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopIPRow, error)
	ListTopIsps(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopIspRow, error)
	ListTopReferers(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopRefererRow, error)
	ListTopUrls(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopUrlRow, error)
	ListTopUserAgents(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopUserAgentRow, error)
	ListTopDomains(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopDomainRow, error)
	SumIspRequests(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, error)
	SumRefererRequests(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, error)
	SumIPCountStats(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, error)
	ListCountryRequests(ctx context.Context, start, end time.Time, scope TrafficScope) ([]CountryRequestRow, error)
	ListCountryRequestsByRequests(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]CountryRequestRow, error)
	ListCountryRequestsByBlocked(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]CountryRequestRow, error)
}

type serverTrafficStatsStore struct {
	db *sql.DB
}

func NewServerTrafficStatsStore(db *sql.DB) ServerTrafficStatsStore {
	return &serverTrafficStatsStore{db: db}
}

func (store *serverTrafficStatsStore) ListBandwidth(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ServerBandwidthPoint, error) {
	query := `
		SELECT server_id, bucket_ts, bandwidth
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		ORDER BY server_id, bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []ServerBandwidthPoint
	for rows.Next() {
		var item ServerBandwidthPoint
		var bucket time.Time
		if err := rows.Scan(&item.ServerID, &bucket, &item.Bandwidth); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListNicRxBandwidthByServer(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ServerBandwidthPoint, error) {
	query := `
		SELECT server_id, bucket_ts, bandwidth_nic_rx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		ORDER BY server_id, bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []ServerBandwidthPoint
	for rows.Next() {
		var item ServerBandwidthPoint
		var bucket time.Time
		if err := rows.Scan(&item.ServerID, &bucket, &item.Bandwidth); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListNicTxBandwidthByServer(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ServerBandwidthPoint, error) {
	query := `
		SELECT server_id, bucket_ts, bandwidth_nic_tx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		ORDER BY server_id, bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []ServerBandwidthPoint
	for rows.Next() {
		var item ServerBandwidthPoint
		var bucket time.Time
		if err := rows.Scan(&item.ServerID, &bucket, &item.Bandwidth); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListL7RxBandwidthByServer(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ServerBandwidthPoint, error) {
	query := `
		SELECT server_id, bucket_ts, bandwidth_l7_rx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		ORDER BY server_id, bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []ServerBandwidthPoint
	for rows.Next() {
		var item ServerBandwidthPoint
		var bucket time.Time
		if err := rows.Scan(&item.ServerID, &bucket, &item.Bandwidth); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListL7TxBandwidthByServer(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ServerBandwidthPoint, error) {
	query := `
		SELECT server_id, bucket_ts, bandwidth_l7_tx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		ORDER BY server_id, bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []ServerBandwidthPoint
	for rows.Next() {
		var item ServerBandwidthPoint
		var bucket time.Time
		if err := rows.Scan(&item.ServerID, &bucket, &item.Bandwidth); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListNicRxBandwidthAggregate(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error) {
	query := `
		SELECT bucket_ts, SUM(bandwidth_nic_rx) AS bandwidth_nic_rx	
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TrafficPoint
	for rows.Next() {
		var item TrafficPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Traffic); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListNicTxBandwidthAggregate(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error) {
	query := `
		SELECT bucket_ts, SUM(bandwidth_nic_tx) AS bandwidth_nic_tx	
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TrafficPoint
	for rows.Next() {
		var item TrafficPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Traffic); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListL7RxBandwidthAggregate(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error) {
	query := `
		SELECT bucket_ts, SUM(bandwidth_l7_rx) AS bandwidth_l7_rx	
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TrafficPoint
	for rows.Next() {
		var item TrafficPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Traffic); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListL7TxBandwidthAggregate(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error) {
	query := `
		SELECT bucket_ts, SUM(bandwidth_l7_tx) AS bandwidth_l7_tx	
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TrafficPoint
	for rows.Next() {
		var item TrafficPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Traffic); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListRequestResponse(ctx context.Context, start, end time.Time, scope TrafficScope) ([]RequestResponsePoint, error) {
	query := `
		SELECT bucket_ts,
		       SUM(request_count) AS request_count,
		       SUM(response_count) AS response_count
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []RequestResponsePoint
	for rows.Next() {
		var item RequestResponsePoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.RequestCount, &item.ResponseCount); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListStatusCodes(ctx context.Context, start, end time.Time, scope TrafficScope) ([]StatusCodePoint, error) {
	query := `
		SELECT bucket_ts,
		       SUM(code200 + code206) AS success_count,
		       SUM(code301 + code302) AS redirect_count,
		       SUM(code400 + code403 + code404 + code444 + code499) AS client_count,
		       SUM(code500 + code502 + code503 + code504 + code904 + code929 + code978) AS server_count
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []StatusCodePoint
	for rows.Next() {
		var item StatusCodePoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Success, &item.Redirect, &item.Client, &item.Server); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) SumBlockedRequests(ctx context.Context, start, end time.Time) (int64, error) {
	var total int64
	row := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(blocked_request_count), 0)
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts < ?`,
		start,
		end,
	)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *serverTrafficStatsStore) ListTopIPs(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopIPRow, error) {
	if limit <= 0 {
		limit = 10
	}
	query := `
		SELECT INET6_NTOA(ip) AS ip,
		       SUM(request_count) AS request_count
		FROM ip_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY ip
		ORDER BY request_count DESC
		LIMIT ?
		`
	args = append(args, limit)
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []TopIPRow
	for rows.Next() {
		var row TopIPRow
		if err := rows.Scan(&row.IP, &row.Requests); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) ListTopIsps(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopIspRow, error) {
	if limit <= 0 {
		limit = 10
	}
	query := `
		SELECT request_isp AS isp,
		       SUM(request_count) AS request_count
		FROM isp_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY request_isp
		ORDER BY request_count DESC
		LIMIT ?
		`
	args = append(args, limit)
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []TopIspRow
	for rows.Next() {
		var row TopIspRow
		if err := rows.Scan(&row.ISP, &row.Requests); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) ListTopReferers(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopRefererRow, error) {
	if limit <= 0 {
		limit = 10
	}
	query := `
		SELECT request_referer AS referer,
		       SUM(request_count) AS request_count
		FROM referer_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY request_referer
		ORDER BY request_count DESC
		LIMIT ?`
	args = append(args, limit)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []TopRefererRow
	for rows.Next() {
		var row TopRefererRow
		if err := rows.Scan(&row.Referer, &row.Requests); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) ListTopUrls(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopUrlRow, error) {
	if limit <= 0 {
		limit = 10
	}
	query := `
		SELECT request_url AS url,
		       SUM(request_count) AS request_count
		FROM url_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY request_url
		ORDER BY request_count DESC
		LIMIT ?
		`
	args = append(args, limit)
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []TopUrlRow
	for rows.Next() {
		var row TopUrlRow
		if err := rows.Scan(&row.URL, &row.Requests); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) ListTopUserAgents(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopUserAgentRow, error) {
	if limit <= 0 {
		limit = 10
	}
	query := `
		SELECT request_useragent AS agent,
		       SUM(request_count) AS request_count
		FROM useragent_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY request_useragent
		ORDER BY request_count DESC
		LIMIT ?`
	args = append(args, limit)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []TopUserAgentRow
	for rows.Next() {
		var row TopUserAgentRow
		if err := rows.Scan(&row.Agent, &row.Requests); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) ListTopDomains(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]TopDomainRow, error) {
	if limit <= 0 {
		limit = 10
	}
	innerQuery := `
		SELECT LOWER(TRIM(BOTH '/' FROM SUBSTRING_INDEX(SUBSTRING_INDEX(SUBSTRING_INDEX(request_url, '://', -1), '/', 1), ':', 1))) AS domain,
		       SUM(request_count) AS request_count
		FROM url_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		  AND request_url LIKE 'http%://%'`
	innerArgs := []any{start, end}
	innerQuery, innerArgs = appendServerScope(innerQuery, innerArgs, scope)
	innerQuery += `
		GROUP BY domain
		HAVING domain <> ''`
	if domain := strings.ToLower(strings.TrimSpace(scope.Domain)); domain != "" {
		innerQuery += ` AND domain = ?`
		innerArgs = append(innerArgs, domain)
	}

	query := fmt.Sprintf(`
		SELECT agg.domain,
		       agg.request_count,
		       COALESCE(s.bandwidth, 0) AS bandwidth,
		       COALESCE(s.cache_ratio, 0) AS cache_ratio,
		       COALESCE(s.status, 'UNKNOWN') AS status
		FROM (%s) agg
		LEFT JOIN sites s ON LOWER(s.domain) = agg.domain
		ORDER BY agg.request_count DESC
		LIMIT ?`, innerQuery)
	innerArgs = append(innerArgs, limit)

	rows, err := store.db.QueryContext(ctx, query, innerArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []TopDomainRow
	for rows.Next() {
		var row TopDomainRow
		if err := rows.Scan(&row.Domain, &row.Requests, &row.Bandwidth, &row.CacheHit, &row.Status); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) SumIspRequests(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, error) {
	var total int64
	query := `
		SELECT COALESCE(COUNT(DISTINCT request_isp), 0)
		FROM isp_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *serverTrafficStatsStore) SumIPCountStats(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, error) {
	var total int64
	query := `
		SELECT COALESCE(COUNT(DISTINCT ip), 0)
		FROM ip_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *serverTrafficStatsStore) SumRefererRequests(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, error) {
	var total int64
	query := `
		SELECT COALESCE(COUNT(DISTINCT request_referer), 0)
		FROM referer_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *serverTrafficStatsStore) ListCountryRequests(ctx context.Context, start, end time.Time, scope TrafficScope) ([]CountryRequestRow, error) {
	query := `
		SELECT country_code,
		       SUM(request_count) AS request_count,
		       SUM(blocked_request_count) AS blocked_request_count
		FROM country_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY country_code
		ORDER BY request_count DESC
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []CountryRequestRow
	for rows.Next() {
		var row CountryRequestRow
		if err := rows.Scan(&row.CountryCode, &row.Requests, &row.Blocked); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) ListCountryRequestsByRequests(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]CountryRequestRow, error) {
	if limit <= 0 {
		limit = 30
	}
	query := `
		SELECT country_code,
		       SUM(request_count) AS request_count,
		       SUM(blocked_request_count) AS blocked_request_count
		FROM country_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY country_code
		ORDER BY request_count DESC
		LIMIT ?
		`
	args = append(args, limit)
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []CountryRequestRow
	for rows.Next() {
		var row CountryRequestRow
		if err := rows.Scan(&row.CountryCode, &row.Requests, &row.Blocked); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) ListCountryRequestsByBlocked(ctx context.Context, start, end time.Time, scope TrafficScope, limit int) ([]CountryRequestRow, error) {
	if limit <= 0 {
		limit = 30
	}
	query := `
		SELECT country_code,
		       SUM(request_count) AS request_count,
		       SUM(blocked_request_count) AS blocked_request_count
		FROM country_request_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY country_code
		ORDER BY blocked_request_count DESC
		LIMIT ?
		`
	args = append(args, limit)
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rowsOut []CountryRequestRow
	for rows.Next() {
		var row CountryRequestRow
		if err := rows.Scan(&row.CountryCode, &row.Requests, &row.Blocked); err != nil {
			return nil, err
		}
		rowsOut = append(rowsOut, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rowsOut, nil
}

func (store *serverTrafficStatsStore) ListNicTxTraffic(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error) {
	query := `
		SELECT bucket_ts, CAST(SUM(traffic_nic_tx) AS UNSIGNED) AS traffic_nic_tx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TrafficPoint
	for rows.Next() {
		var item TrafficPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Traffic); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListNicRxTraffic(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error) {
	query := `
		SELECT bucket_ts, CAST(SUM(traffic_nic_rx) AS UNSIGNED) AS traffic_nic_rx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TrafficPoint
	for rows.Next() {
		var item TrafficPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Traffic); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListL7TxTraffic(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error) {
	query := `
		SELECT bucket_ts, CAST(SUM(traffic_l7_tx) AS UNSIGNED) AS traffic_l7_tx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TrafficPoint
	for rows.Next() {
		var item TrafficPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Traffic); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListL7RxTraffic(ctx context.Context, start, end time.Time, scope TrafficScope) ([]TrafficPoint, error) {
	query := `
		SELECT bucket_ts, CAST(SUM(traffic_l7_rx) AS UNSIGNED) AS traffic_l7_rx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TrafficPoint
	for rows.Next() {
		var item TrafficPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Traffic); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListIpCount(ctx context.Context, start, end time.Time, scope TrafficScope) ([]IpCountPoint, error) {
	query := `
		SELECT bucket_ts, SUM(ip_count) AS ip_count
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []IpCountPoint
	for rows.Next() {
		var item IpCountPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Count); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListBlockedRequestSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]BlockedRequestPoint, error) {
	query := `
		SELECT bucket_ts, SUM(blocked_request_count) AS blocked_request_count
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []BlockedRequestPoint
	for rows.Next() {
		var item BlockedRequestPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &item.Count); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListMethodSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]MethodSeriesPoint, error) {
	query := `
		SELECT bucket_ts,
		       SUM(get_count) AS get_count,
		       SUM(post_count) AS post_count,
		       SUM(delete_count) AS delete_count,
		       SUM(put_count) AS put_count,
		       SUM(head_count) AS head_count,
		       SUM(patch_count) AS patch_count,
		       SUM(options_count) AS options_count,
		       SUM(others_count) AS others_count
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []MethodSeriesPoint
	for rows.Next() {
		var item MethodSeriesPoint
		var bucket time.Time
		if err := rows.Scan(
			&bucket,
			&item.GetCount,
			&item.PostCount,
			&item.DeleteCount,
			&item.PutCount,
			&item.HeadCount,
			&item.PatchCount,
			&item.OptionsCount,
			&item.OthersCount,
		); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) ListProtocolSeries(ctx context.Context, start, end time.Time, scope TrafficScope) ([]ProtocolSeriesPoint, error) {
	query := `
		SELECT bucket_ts,
		       SUM(http1_0_count) AS http1_0_count,
		       SUM(http1_1_count) AS http1_1_count,
		       SUM(http2_count) AS http2_count,
		       SUM(http3_count) AS http3_count
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts
		`
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []ProtocolSeriesPoint
	for rows.Next() {
		var item ProtocolSeriesPoint
		var bucket time.Time
		if err := rows.Scan(
			&bucket,
			&item.Http1_0,
			&item.Http1_1,
			&item.Http2,
			&item.Http3,
		); err != nil {
			return nil, err
		}
		item.Timestamp = bucket.Format(time.RFC3339)
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (store *serverTrafficStatsStore) SumStatusCodes(ctx context.Context, start, end time.Time, scope TrafficScope) (StatusCodeSummary, error) {
	var summary StatusCodeSummary
	query := `
		SELECT
			COALESCE(SUM(code200), 0),
			COALESCE(SUM(code206), 0),
			COALESCE(SUM(code301), 0),
			COALESCE(SUM(code302), 0),
			COALESCE(SUM(code400), 0),
			COALESCE(SUM(code403), 0),
			COALESCE(SUM(code404), 0),
			COALESCE(SUM(code444), 0),
			COALESCE(SUM(code499), 0),
			COALESCE(SUM(code500), 0),
			COALESCE(SUM(code502), 0),
			COALESCE(SUM(code503), 0),
			COALESCE(SUM(code504), 0),
			COALESCE(SUM(code904), 0),
			COALESCE(SUM(code929), 0),
			COALESCE(SUM(code978), 0)
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(
		&summary.Code200,
		&summary.Code206,
		&summary.Code301,
		&summary.Code302,
		&summary.Code400,
		&summary.Code403,
		&summary.Code404,
		&summary.Code444,
		&summary.Code499,
		&summary.Code500,
		&summary.Code502,
		&summary.Code503,
		&summary.Code504,
		&summary.Code904,
		&summary.Code929,
		&summary.Code978,
	); err != nil {
		return StatusCodeSummary{}, err
	}
	return summary, nil
}

func (store *serverTrafficStatsStore) SumMethods(ctx context.Context, start, end time.Time, scope TrafficScope) (MethodSummary, error) {
	var summary MethodSummary
	query := `
		SELECT
			COALESCE(SUM(get_count), 0),
			COALESCE(SUM(post_count), 0),
			COALESCE(SUM(delete_count), 0),
			COALESCE(SUM(put_count), 0),
			COALESCE(SUM(head_count), 0),
			COALESCE(SUM(patch_count), 0),
			COALESCE(SUM(options_count), 0),
			COALESCE(SUM(others_count), 0)
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(
		&summary.GetCount,
		&summary.PostCount,
		&summary.DeleteCount,
		&summary.PutCount,
		&summary.HeadCount,
		&summary.PatchCount,
		&summary.OptionsCount,
		&summary.OthersCount,
	); err != nil {
		return MethodSummary{}, err
	}
	return summary, nil
}

func (store *serverTrafficStatsStore) SumProtocols(ctx context.Context, start, end time.Time, scope TrafficScope) (ProtocolSummary, error) {
	var summary ProtocolSummary
	query := `
		SELECT
			COALESCE(SUM(http1_0_count), 0),
			COALESCE(SUM(http1_1_count), 0),
			COALESCE(SUM(http2_count), 0),
			COALESCE(SUM(http3_count), 0)
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(
		&summary.Http1_0,
		&summary.Http1_1,
		&summary.Http2,
		&summary.Http3,
	); err != nil {
		return ProtocolSummary{}, err
	}
	return summary, nil
}

func (store *serverTrafficStatsStore) SumTotals(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, int64, int64, int64, int64, int64, error) {
	var totalNicRxTraffic int64
	var totalNicTxTraffic int64
	var totalL7RxTraffic int64
	var totalL7TxTraffic int64
	var totalRequest int64
	var totalResponse int64
	query := `
		SELECT
			COALESCE(CAST(SUM(traffic_nic_rx) AS UNSIGNED), 0),
			COALESCE(CAST(SUM(traffic_nic_tx) AS UNSIGNED), 0),
			COALESCE(CAST(SUM(traffic_l7_rx) AS UNSIGNED), 0),
			COALESCE(CAST(SUM(traffic_l7_tx) AS UNSIGNED), 0),
			COALESCE(SUM(request_count), 0),
			COALESCE(SUM(response_count), 0),
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&totalNicRxTraffic, &totalNicTxTraffic, &totalL7RxTraffic, &totalL7TxTraffic, &totalRequest, &totalResponse); err != nil {
		return 0, 0, 0, 0, 0, 0, nil
	}
	return totalNicRxTraffic, totalNicTxTraffic, totalL7RxTraffic, totalL7TxTraffic, totalRequest, totalResponse, nil
}

func (store *serverTrafficStatsStore) SumSecurityTotals(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, int64, int64, int64, error) {
	var totalRequest int64
	var blockedRequest int64
	var totalIp int64
	var blockedIp int64
	query := `
		SELECT
			COALESCE(SUM(request_count), 0),
			COALESCE(SUM(blocked_request_count), 0),
			COALESCE(SUM(ip_count), 0),
			COALESCE(SUM(blocked_ip_count), 0)
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&totalRequest, &blockedRequest, &totalIp, &blockedIp); err != nil {
		return 0, 0, 0, 0, err
	}
	return totalRequest, blockedRequest, totalIp, blockedIp, nil
}

func (store *serverTrafficStatsStore) LatestNicRxBandwidth(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, time.Time, error) {
	var bucket time.Time
	var bandwidthNicRx int64
	query := `
		SELECT bucket_ts, SUM(bandwidth_nic_rx) AS bandwidth_nic_rx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts DESC
		LIMIT 1
		`
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&bucket, &bandwidthNicRx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, time.Time{}, errors.New("no data found")
		}
		return 0, time.Time{}, errors.New("failed to load latest nic rx bandwidth")
	}
	return bandwidthNicRx, bucket, nil
}

func (store *serverTrafficStatsStore) LatestL7RxBandwidth(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, time.Time, error) {
	var bucket time.Time
	var bandwidthL7Rx int64
	query := `
		SELECT bucket_ts, SUM(bandwidth_l7_rx) AS bandwidth_l7_rx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts DESC
		LIMIT 1
		`
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&bucket, &bandwidthL7Rx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, time.Time{}, errors.New("no data found")
		}
		return 0, time.Time{}, errors.New("failed to load latest l7 rx bandwidth")
	}
	return bandwidthL7Rx, bucket, nil
}

func (store *serverTrafficStatsStore) LatestL7TxBandwidth(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, time.Time, error) {
	var bucket time.Time
	var bandwidthL7Tx int64
	query := `
		SELECT bucket_ts, SUM(bandwidth_l7_tx) AS bandwidth_l7_tx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts DESC
		LIMIT 1
		`
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&bucket, &bandwidthL7Tx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, time.Time{}, errors.New("failed to load latest l7 tx bandwidth")
		}
		return 0, time.Time{}, errors.New("failed to load latest l7 tx bandwidth")
	}
	return bandwidthL7Tx, bucket, nil
}

func (store *serverTrafficStatsStore) LatestNicTxBandwidth(ctx context.Context, start, end time.Time, scope TrafficScope) (int64, time.Time, error) {
	var bucket time.Time
	var bandwidthNicTx int64
	query := `
		SELECT bucket_ts, SUM(bandwidth_nic_tx) AS bandwidth_nic_tx
		FROM server_traffic_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendServerScope(query, args, scope)
	query += `
		GROUP BY bucket_ts
		ORDER BY bucket_ts DESC
		LIMIT 1
		`
	row := store.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&bucket, &bandwidthNicTx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, time.Time{}, errors.New("failed to load latest nic tx bandwidth")
		}
		return 0, time.Time{}, errors.New("failed to load latest nic tx bandwidth")
	}
	return bandwidthNicTx, bucket, nil
}
