package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vue-project-backend/internal/api"
	"vue-project-backend/internal/config"
	"vue-project-backend/internal/db"
	"vue-project-backend/internal/store"
	"vue-project-backend/internal/worker"
)

func main() {
	cfg := config.Load()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connection, err := db.Open(cfg)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			log.Printf("database close failed: %v", closeErr)
		}
	}()

	redisClient, err := db.OpenRedis(cfg)
	if err != nil {
		log.Fatalf("redis connection failed: %v", err)
	}
	defer func() {
		if closeErr := redisClient.Close(); closeErr != nil {
			log.Printf("redis close failed: %v", closeErr)
		}
	}()

	userStore := store.NewUserStore(connection)
	l4Store := store.NewL4Store(connection)
	l4WhitelistStore := store.NewL4WhitelistStore(connection)
	l4BlacklistStore := store.NewL4BlacklistStore(connection)
	serverStore := store.NewServerStore(connection)
	l4LiveAttackStore := store.NewL4LiveAttackStore(connection)
	l4AttackStatsStore := store.NewL4AttackStatsStore(connection)
	securityEventStore := store.NewSecurityEventStore(connection)
	serverTrafficStatsStore := store.NewServerTrafficStatsStore(connection)
	wafWhitelistStore := store.NewWafWhitelistStore(connection)
	wafBlacklistStore := store.NewWafBlacklistStore(connection)
	wafGeoStore := store.NewWafGeoStore(connection)
	wafAntiCcStore := store.NewWafAntiCcStore(connection)
	wafAntiHeaderStore := store.NewWafAntiHeaderStore(connection)
	wafIntervalStore := store.NewWafIntervalStore(connection)
	wafSecondStore := store.NewWafSecondStore(connection)
	wafResponseStore := store.NewWafResponseStore(connection)
	wafUserAgentStore := store.NewWafUserAgentStore(connection)
	upstreamStore := store.NewUpstreamServerStore(connection)
	blacklistStore := store.NewBlacklistStore(redisClient)
	handler := api.NewRouter(cfg, userStore, serverStore, l4Store, l4WhitelistStore, l4BlacklistStore, l4LiveAttackStore, l4AttackStatsStore, securityEventStore, serverTrafficStatsStore, wafWhitelistStore, wafBlacklistStore, wafGeoStore, wafAntiCcStore, wafAntiHeaderStore, wafIntervalStore, wafSecondStore, wafResponseStore, wafUserAgentStore, upstreamStore, blacklistStore)

	// Start background worker to periodically collect IP request statistics
	// from each server and store them into the database.
	worker.StartIPRequestStatsCollector(ctx, cfg, connection, serverStore)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,
		// Do not set ReadTimeout/WriteTimeout globally: they break long-lived
		// WebSocket streams (access log tail). Per-request limits use ReadHeaderTimeout.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("backend listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	// Cancel background workers.
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}
