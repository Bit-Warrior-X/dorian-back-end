package api

import (
	"net/http"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

func NewRouter(
	cfg config.Config,
	users store.UserStore,
	servers store.ServerStore,
	l4 store.L4Store,
	l4Whitelist store.L4WhitelistStore,
	l4Blacklist store.L4BlacklistStore,
	l4LiveAttack store.L4LiveAttackStore,
	l4AttackStats store.L4AttackStatsStore,
	securityEvents store.SecurityEventStore,
	serverTrafficStats store.ServerTrafficStatsStore,
	wafWhitelist store.WafWhitelistStore,
	wafBlacklist store.WafBlacklistStore,
	wafGeo store.WafGeoStore,
	wafAntiCc store.WafAntiCcStore,
	wafAntiHeader store.WafAntiHeaderStore,
	wafInterval store.WafIntervalStore,
	wafSecond store.WafSecondStore,
	wafResponse store.WafResponseStore,
	wafUserAgent store.WafUserAgentStore,
	upstreamServers store.UpstreamServerStore,
	listeningPorts store.ListeningPortStore,
	cacheRules store.CacheRuleStore,
	blacklist store.BlacklistStore,
) http.Handler {
	mux := http.NewServeMux()

	agentClient := NewAgentClient(cfg)
	registerRoutes(mux, cfg, agentClient, users, servers, l4, l4Whitelist, l4Blacklist, l4LiveAttack, l4AttackStats, securityEvents, serverTrafficStats, wafWhitelist, wafBlacklist, wafGeo, wafAntiCc, wafAntiHeader, wafInterval, wafSecond, wafResponse, wafUserAgent, upstreamServers, listeningPorts, cacheRules, blacklist)

	handler := withCORS(cfg, mux)
	handler = withRequestLogging(handler)

	return handler
}
