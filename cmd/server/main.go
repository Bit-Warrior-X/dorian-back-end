package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vue-project-backend/internal/acme"
	"vue-project-backend/internal/api"
	"vue-project-backend/internal/applog"
	"vue-project-backend/internal/config"
	"vue-project-backend/internal/db"
	"vue-project-backend/internal/store"
	"vue-project-backend/internal/worker"
)

func main() {
	applog.Install("api")
	cfg := config.Load()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connection, err := db.Open(cfg)
	if err != nil {
		applog.Errorf("api", "startup_failed", map[string]any{"step": "database", "error": err.Error()})
		os.Exit(1)
	}
	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			applog.Warnf("api", "shutdown_warning", map[string]any{"step": "database_close", "error": closeErr.Error()})
		}
	}()

	redisClient, err := db.OpenRedis(cfg)
	if err != nil {
		applog.Errorf("api", "startup_failed", map[string]any{"step": "redis", "error": err.Error()})
		os.Exit(1)
	}
	defer func() {
		if closeErr := redisClient.Close(); closeErr != nil {
			applog.Warnf("api", "shutdown_warning", map[string]any{"step": "redis_close", "error": closeErr.Error()})
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
	listeningPortStore := store.NewListeningPortStore(connection)
	cacheRuleStore := store.NewCacheRuleStore(connection)
	compressStore := store.NewCompressStore(connection)
	blacklistStore := store.NewBlacklistStore(redisClient)
	siteStore := store.NewSiteStore(connection)
	wafRuleStore := store.NewWafRuleStore(connection)
	siteListeningPortStore := store.NewSiteListeningPortStore(connection)
	auditLogStore := store.NewAuditLogStore(connection)
	apiTokenStore := store.NewAPITokenStore(connection)
	licensePlanStore := store.NewLicensePlanStore(connection)
	certIssuer := acme.NewIssuer(cfg, siteStore)
	handler := api.NewRouter(cfg, userStore, serverStore, l4Store, l4WhitelistStore, l4BlacklistStore, l4LiveAttackStore, l4AttackStatsStore, securityEventStore, serverTrafficStatsStore, wafWhitelistStore, wafBlacklistStore, wafGeoStore, wafAntiCcStore, wafAntiHeaderStore, wafIntervalStore, wafSecondStore, wafResponseStore, wafUserAgentStore, upstreamStore, listeningPortStore, cacheRuleStore, compressStore, blacklistStore, siteStore, wafRuleStore, siteListeningPortStore, auditLogStore, apiTokenStore, licensePlanStore, certIssuer)

	// Start background worker to periodically collect IP request statistics
	// from each server and store them into the database.
	worker.StartIPRequestStatsCollector(ctx, cfg, connection, serverStore)
	certIssuer.Start(ctx)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,
		// Do not set ReadTimeout/WriteTimeout globally: they break long-lived
		// WebSocket streams (access log tail). Per-request limits use ReadHeaderTimeout.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		applog.Infof("api", "listening", map[string]any{"addr": server.Addr})
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			applog.Errorf("api", "server_error", map[string]any{"error": err.Error()})
			os.Exit(1)
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
		applog.Warnf("api", "shutdown_failed", map[string]any{"error": err.Error()})
	} else {
		applog.Infof("api", "shutdown_ok", nil)
	}
}
