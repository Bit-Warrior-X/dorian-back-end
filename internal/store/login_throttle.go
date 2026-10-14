package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	loginFailAccountKey = "auth:login_fail:acct:"
	loginFailIPKey      = "auth:login_fail:ip:"
	loginLockAccountKey = "auth:login_lock:acct:"
	loginLockIPKey      = "auth:login_lock:ip:"
)

type LoginThrottleConfig struct {
	MaxAccountFailures int
	MaxIPFailures      int
	Window             time.Duration
	Lockout            time.Duration
}

// LoginThrottleStore counts failed sign-in attempts (password or 2FA code) per
// account and per client IP, and locks either one out once its limit is hit.
type LoginThrottleStore interface {
	// RetryAfter returns how long the caller must wait, or 0 if not locked.
	RetryAfter(ctx context.Context, ip, account string) (time.Duration, error)
	RecordFailure(ctx context.Context, ip, account string) error
	RecordSuccess(ctx context.Context, account string) error
}

type loginThrottleStore struct {
	rdb *redis.Client
	cfg LoginThrottleConfig
}

func NewLoginThrottleStore(rdb *redis.Client, cfg LoginThrottleConfig) LoginThrottleStore {
	if cfg.MaxAccountFailures <= 0 {
		cfg.MaxAccountFailures = 10
	}
	if cfg.MaxIPFailures <= 0 {
		cfg.MaxIPFailures = 30
	}
	if cfg.Window <= 0 {
		cfg.Window = 15 * time.Minute
	}
	if cfg.Lockout <= 0 {
		cfg.Lockout = 15 * time.Minute
	}
	return &loginThrottleStore{rdb: rdb, cfg: cfg}
}

// accountKey hashes the email so Redis does not hold a list of attempted addresses.
func accountKey(account string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(account))))
	return hex.EncodeToString(sum[:16])
}

func (s *loginThrottleStore) RetryAfter(ctx context.Context, ip, account string) (time.Duration, error) {
	var wait time.Duration
	keys := make([]string, 0, 2)
	if strings.TrimSpace(account) != "" {
		keys = append(keys, loginLockAccountKey+accountKey(account))
	}
	if strings.TrimSpace(ip) != "" {
		keys = append(keys, loginLockIPKey+ip)
	}
	for _, key := range keys {
		ttl, err := s.rdb.PTTL(ctx, key).Result()
		if err != nil {
			return 0, err
		}
		if ttl > wait {
			wait = ttl
		}
	}
	return wait, nil
}

func (s *loginThrottleStore) RecordFailure(ctx context.Context, ip, account string) error {
	if strings.TrimSpace(account) != "" {
		if err := s.bump(ctx, loginFailAccountKey+accountKey(account), loginLockAccountKey+accountKey(account), s.cfg.MaxAccountFailures); err != nil {
			return err
		}
	}
	if strings.TrimSpace(ip) != "" {
		if err := s.bump(ctx, loginFailIPKey+ip, loginLockIPKey+ip, s.cfg.MaxIPFailures); err != nil {
			return err
		}
	}
	return nil
}

func (s *loginThrottleStore) bump(ctx context.Context, counterKey, lockKey string, limit int) error {
	count, err := s.rdb.Incr(ctx, counterKey).Result()
	if err != nil {
		return err
	}
	// EXPIRE NX needs Redis 7; setting the TTL on the first hit keeps a fixed window on 6.x.
	if count == 1 {
		if err := s.rdb.Expire(ctx, counterKey, s.cfg.Window).Err(); err != nil {
			return err
		}
	}
	if count < int64(limit) {
		return nil
	}
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, lockKey, "1", s.cfg.Lockout)
	pipe.Del(ctx, counterKey)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *loginThrottleStore) RecordSuccess(ctx context.Context, account string) error {
	if strings.TrimSpace(account) == "" {
		return nil
	}
	return s.rdb.Del(ctx, loginFailAccountKey+accountKey(account)).Err()
}
