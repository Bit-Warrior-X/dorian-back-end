package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type BlockReasonRuleRow struct {
	RuleType string `json:"ruleType"`
	Label    string `json:"label"`
	Count    int64  `json:"count"`
	IPCount  int64  `json:"ipCount,omitempty"`
}

type BlockReasonBucketRow struct {
	ServerID     int64
	SiteID       int64
	RuleType     string
	RuleID       string
	RequestCount int64
	IPCount      int64
}

var wafRuleTypeLabels = map[string]string{
	"blacklist":           "IP / URL blacklist",
	"geo":                 "GEO block",
	"anti-cc":             "Anti CC challenge",
	"second-freq-limit":   "Per-second limit",
	"interval-freq-limit": "Interval limit",
	"user-agent":          "User agent",
	"anti-header":         "Anti header",
	"response-freq":       "Response freq",
	"ip-reputation":       "IP reputation",
	"temporary-block":     "Already on Temporary blocks",
	"other":               "Other",
}

func WafRuleTypeLabel(ruleType string) string {
	key := strings.ToLower(strings.TrimSpace(ruleType))
	if label, ok := wafRuleTypeLabels[key]; ok {
		return label
	}
	if key == "" {
		return "Unknown"
	}
	return ruleType
}

func (store *serverTrafficStatsStore) ReplaceBlockReasonBucket(ctx context.Context, serverID int64, bucket time.Time, rows []BlockReasonBucketRow) error {
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
		`DELETE FROM block_reason_stats WHERE server_id = ? AND bucket_ts = ?`,
		serverID, bucket,
	); err != nil {
		return fmt.Errorf("clear block_reason_stats: %w", err)
	}
	if len(rows) == 0 {
		return tx.Commit()
	}

	placeholders := make([]string, 0, len(rows))
	args := make([]any, 0, len(rows)*7)
	for _, row := range rows {
		ruleType := strings.ToLower(strings.TrimSpace(row.RuleType))
		if ruleType == "" || row.RequestCount <= 0 {
			continue
		}
		ruleID := strings.TrimSpace(row.RuleID)
		if len(ruleID) > 128 {
			ruleID = ruleID[:128]
		}
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?, ?)")
		args = append(args, serverID, row.SiteID, bucket, ruleType, ruleID, row.RequestCount, row.IPCount)
	}
	if len(placeholders) == 0 {
		return tx.Commit()
	}
	query := `
		INSERT INTO block_reason_stats (
			server_id, site_id, bucket_ts, rule_type, rule_id, request_count, ip_count
		) VALUES ` + strings.Join(placeholders, ",")
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("insert block_reason_stats: %w", err)
	}
	return tx.Commit()
}

func (store *serverTrafficStatsStore) ListBlockReasonRuleTypes(ctx context.Context, start, end time.Time, scope TrafficScope) ([]BlockReasonRuleRow, error) {
	query := `
		SELECT rule_type,
		       COALESCE(SUM(request_count), 0) AS requests,
		       COALESCE(SUM(ip_count), 0) AS ips
		FROM block_reason_stats
		WHERE bucket_ts >= ? AND bucket_ts <= ?`
	args := []any{start, end}
	query, args = appendTrafficScope(query, args, scope, true)
	query += `
		GROUP BY rule_type
		HAVING requests > 0
		ORDER BY requests DESC`

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]BlockReasonRuleRow, 0)
	for rows.Next() {
		var row BlockReasonRuleRow
		if err := rows.Scan(&row.RuleType, &row.Count, &row.IPCount); err != nil {
			return nil, err
		}
		row.Label = WafRuleTypeLabel(row.RuleType)
		out = append(out, row)
	}
	return out, rows.Err()
}
