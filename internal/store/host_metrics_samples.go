package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"
)

// HostMetricsSample is a minute-bucketed CPU/RAM snapshot for one edge.
type HostMetricsSample struct {
	ServerID         int64
	BucketTS         time.Time
	CPUPercent       float64
	MemoryUsedBytes  int64
	MemoryTotalBytes int64
}

// HostMetricsSampleStore persists edge host metrics for attack peak lookups.
type HostMetricsSampleStore interface {
	EnsureSchema(ctx context.Context) error
	Upsert(ctx context.Context, sample HostMetricsSample) error
	Nearest(ctx context.Context, serverID int64, at time.Time, maxSkew time.Duration) (HostMetricsSample, error)
	// NearestInRange returns the sample closest to at that also falls inside
	// [start, end]. Used so "Host at peak" never picks a quiet post-attack minute.
	NearestInRange(ctx context.Context, serverID int64, at, start, end time.Time) (HostMetricsSample, error)
	ListUnderAttackServerIDs(ctx context.Context) ([]int64, error)
	PruneOlderThan(ctx context.Context, olderThan time.Duration) (int64, error)
}

type hostMetricsSampleStore struct {
	db *sql.DB
}

func NewHostMetricsSampleStore(db *sql.DB) HostMetricsSampleStore {
	return &hostMetricsSampleStore{db: db}
}

func (store *hostMetricsSampleStore) EnsureSchema(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS host_metrics_samples (
			server_id BIGINT NOT NULL,
			bucket_ts DATETIME NOT NULL,
			cpu_percent DOUBLE NOT NULL DEFAULT 0,
			memory_used_bytes BIGINT NOT NULL DEFAULT 0,
			memory_total_bytes BIGINT NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (server_id, bucket_ts),
			KEY host_metrics_samples_bucket (bucket_ts),
			CONSTRAINT host_metrics_samples_server_fk
				FOREIGN KEY (server_id) REFERENCES servers (id)
				ON DELETE CASCADE ON UPDATE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`)
	return err
}

func truncateToMinute(ts time.Time) time.Time {
	t := ts.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)
}

func (store *hostMetricsSampleStore) Upsert(ctx context.Context, sample HostMetricsSample) error {
	if sample.ServerID <= 0 {
		return fmt.Errorf("invalid server id")
	}
	bucket := truncateToMinute(sample.BucketTS)
	if bucket.IsZero() {
		bucket = truncateToMinute(time.Now().UTC())
	}
	_, err := store.db.ExecContext(ctx, `
		INSERT INTO host_metrics_samples (
			server_id, bucket_ts, cpu_percent, memory_used_bytes, memory_total_bytes
		) VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			cpu_percent = VALUES(cpu_percent),
			memory_used_bytes = VALUES(memory_used_bytes),
			memory_total_bytes = VALUES(memory_total_bytes)`,
		sample.ServerID,
		bucket,
		sample.CPUPercent,
		sample.MemoryUsedBytes,
		sample.MemoryTotalBytes,
	)
	if err != nil {
		return fmt.Errorf("upsert host metrics sample: %w", err)
	}
	return nil
}

func (store *hostMetricsSampleStore) Nearest(ctx context.Context, serverID int64, at time.Time, maxSkew time.Duration) (HostMetricsSample, error) {
	if serverID <= 0 || at.IsZero() {
		return HostMetricsSample{}, errNotFound
	}
	if maxSkew <= 0 {
		maxSkew = 90 * time.Second
	}
	at = at.UTC()
	return store.NearestInRange(ctx, serverID, at, at.Add(-maxSkew), at.Add(maxSkew))
}

func (store *hostMetricsSampleStore) NearestInRange(ctx context.Context, serverID int64, at, start, end time.Time) (HostMetricsSample, error) {
	if serverID <= 0 || at.IsZero() || start.IsZero() || end.IsZero() {
		return HostMetricsSample{}, errNotFound
	}
	at = at.UTC()
	start = start.UTC()
	end = end.UTC()
	if end.Before(start) {
		start, end = end, start
	}

	var (
		bucket time.Time
		cpu    float64
		used   int64
		total  int64
	)
	err := store.db.QueryRowContext(ctx, `
		SELECT bucket_ts, cpu_percent, memory_used_bytes, memory_total_bytes
		FROM host_metrics_samples
		WHERE server_id = ?
		  AND bucket_ts BETWEEN ? AND ?
		ORDER BY ABS(TIMESTAMPDIFF(SECOND, bucket_ts, ?)) ASC, bucket_ts DESC
		LIMIT 1`,
		serverID, start, end, at,
	).Scan(&bucket, &cpu, &used, &total)
	if err == sql.ErrNoRows {
		return HostMetricsSample{}, errNotFound
	}
	if err != nil {
		return HostMetricsSample{}, fmt.Errorf("nearest host metrics sample: %w", err)
	}
	return HostMetricsSample{
		ServerID:         serverID,
		BucketTS:         bucket.UTC(),
		CPUPercent:       cpu,
		MemoryUsedBytes:  used,
		MemoryTotalBytes: total,
	}, nil
}

func (store *hostMetricsSampleStore) ListUnderAttackServerIDs(ctx context.Context) ([]int64, error) {
	// Include recently ended L7 incidents so short attacks still get a sample
	// near peak (sampler ticks every minute; many L7 floods last < 2 minutes).
	// L4: security_events catch fragmented Sparta campaigns even when
	// l4_live_attack is sparse; keep sampling a few minutes after the last signal.
	rows, err := store.db.QueryContext(ctx, `
		SELECT DISTINCT server_id FROM (
			SELECT server_id
			FROM l7_attacks
			WHERE server_id > 0
			  AND (
				status = 'active'
				OR (status = 'ended' AND COALESCE(ended_at, updated_at) >= UTC_TIMESTAMP() - INTERVAL 3 MINUTE)
			)
			UNION
			SELECT server_id
			FROM l4_live_attack
			WHERE server_id > 0
			  AND created_at >= UTC_TIMESTAMP() - INTERVAL 15 MINUTE
			UNION
			SELECT server_id
			FROM security_events
			WHERE server_id > 0
			  AND command IN ('report_attack', 'report_protection', 'report_block_ip')
			  AND created_at >= UTC_TIMESTAMP() - INTERVAL 15 MINUTE
		) AS active_edges`)
	if err != nil {
		return nil, fmt.Errorf("list under-attack servers: %w", err)
	}
	defer rows.Close()

	out := make([]int64, 0, 8)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan under-attack server: %w", err)
		}
		if id > 0 {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

func (store *hostMetricsSampleStore) PruneOlderThan(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		olderThan = 14 * 24 * time.Hour
	}
	cutoff := time.Now().UTC().Add(-olderThan)
	res, err := store.db.ExecContext(ctx, `
		DELETE FROM host_metrics_samples WHERE bucket_ts < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune host metrics samples: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SampleSkewSeconds returns how far the sample bucket is from the target instant.
func SampleSkewSeconds(sample HostMetricsSample, at time.Time) int64 {
	if sample.BucketTS.IsZero() || at.IsZero() {
		return 0
	}
	skew := sample.BucketTS.Sub(at.UTC()).Seconds()
	return int64(math.Round(math.Abs(skew)))
}
