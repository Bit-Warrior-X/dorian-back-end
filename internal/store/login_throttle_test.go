package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	// DB 15 keeps test keys away from application data in DB 0.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379", DB: 15})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("redis not available: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func TestLoginThrottleLocksAccount(t *testing.T) {
	rdb := newTestRedis(t)
	ctx := context.Background()
	throttle := NewLoginThrottleStore(rdb, LoginThrottleConfig{
		MaxAccountFailures: 3, MaxIPFailures: 100, Window: time.Minute, Lockout: time.Minute,
	})
	account := fmt.Sprintf("user-%d@example.com", time.Now().UnixNano())
	ip := "192.0.2.1"
	t.Cleanup(func() {
		rdb.Del(ctx, loginFailAccountKey+accountKey(account), loginLockAccountKey+accountKey(account),
			loginFailIPKey+ip, loginLockIPKey+ip)
	})

	for i := 0; i < 2; i++ {
		if err := throttle.RecordFailure(ctx, ip, account); err != nil {
			t.Fatal(err)
		}
	}
	if wait, _ := throttle.RetryAfter(ctx, ip, account); wait != 0 {
		t.Fatalf("expected no lock after 2 failures, got %v", wait)
	}
	if err := throttle.RecordFailure(ctx, ip, account); err != nil {
		t.Fatal(err)
	}
	wait, err := throttle.RetryAfter(ctx, "", account)
	if err != nil {
		t.Fatal(err)
	}
	if wait <= 0 || wait > time.Minute {
		t.Fatalf("expected account lock up to 1m, got %v", wait)
	}
}

func TestLoginThrottleSuccessResetsAccountCounter(t *testing.T) {
	rdb := newTestRedis(t)
	ctx := context.Background()
	throttle := NewLoginThrottleStore(rdb, LoginThrottleConfig{
		MaxAccountFailures: 3, MaxIPFailures: 100, Window: time.Minute, Lockout: time.Minute,
	})
	account := fmt.Sprintf("user-%d@example.com", time.Now().UnixNano())
	ip := "192.0.2.2"
	t.Cleanup(func() {
		rdb.Del(ctx, loginFailAccountKey+accountKey(account), loginLockAccountKey+accountKey(account),
			loginFailIPKey+ip, loginLockIPKey+ip)
	})

	_ = throttle.RecordFailure(ctx, ip, account)
	_ = throttle.RecordFailure(ctx, ip, account)
	if err := throttle.RecordSuccess(ctx, account); err != nil {
		t.Fatal(err)
	}
	_ = throttle.RecordFailure(ctx, ip, account)
	if wait, _ := throttle.RetryAfter(ctx, ip, account); wait != 0 {
		t.Fatalf("expected counter reset by success, got lock %v", wait)
	}
}

func TestLoginThrottleLocksIPAcrossAccounts(t *testing.T) {
	rdb := newTestRedis(t)
	ctx := context.Background()
	throttle := NewLoginThrottleStore(rdb, LoginThrottleConfig{
		MaxAccountFailures: 100, MaxIPFailures: 3, Window: time.Minute, Lockout: time.Minute,
	})
	ip := fmt.Sprintf("192.0.2.%d", time.Now().UnixNano()%200+10)
	t.Cleanup(func() { rdb.Del(ctx, loginFailIPKey+ip, loginLockIPKey+ip) })

	for i := 0; i < 3; i++ {
		account := fmt.Sprintf("spray-%d-%d@example.com", time.Now().UnixNano(), i)
		_ = throttle.RecordFailure(ctx, ip, account)
		t.Cleanup(func() { rdb.Del(ctx, loginFailAccountKey+accountKey(account)) })
	}
	if wait, _ := throttle.RetryAfter(ctx, ip, "someone-else@example.com"); wait <= 0 {
		t.Fatal("expected IP lock after spraying multiple accounts")
	}
}
