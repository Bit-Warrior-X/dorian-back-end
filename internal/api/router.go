package api

import (
	"net/http"

	"vue-project-backend/internal/acme"
	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

func NewRouter(
	cfg config.Config,
	users store.UserStore,
	mfa store.MFAStore,
	loginThrottle store.LoginThrottleStore,
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
	compressSettings store.CompressStore,
	blacklist store.BlacklistStore,
	sites store.SiteStore,
	wafRules store.WafRuleStore,
	siteListeningPorts store.SiteListeningPortStore,
	auditLogs store.AuditLogStore,
	apiTokens store.APITokenStore,
	licensePlans store.LicensePlanStore,
	notifications store.NotificationStore,
	sessions store.AuthSessionStore,
	panelSettings store.PanelSettingsStore,
	userTokens store.UserTokenStore,
	certIssuer *acme.Issuer,
) http.Handler {
	mux := http.NewServeMux()

	agentClient := NewAgentClient(cfg)
	configureL7Edge(cfg)
	account := newAccountServices(cfg, users, mfa, sessions, panelSettings, userTokens, auditLogs)
	registerRoutes(mux, cfg, agentClient, account, users, mfa, loginThrottle, auditLogs, apiTokens, licensePlans, servers, l4, l4Whitelist, l4Blacklist, l4LiveAttack, l4AttackStats, securityEvents, serverTrafficStats, wafWhitelist, wafBlacklist, wafGeo, wafAntiCc, wafAntiHeader, wafInterval, wafSecond, wafResponse, wafUserAgent, upstreamServers, listeningPorts, cacheRules, compressSettings, blacklist, sites, wafRules, siteListeningPorts, certIssuer)
	registerNotificationRoutes(mux, notifications)
	registerAccountRoutes(mux, account)

	auditResolver := &auditResolver{users: users, servers: servers, sites: sites, wafRules: wafRules, tokens: apiTokens}

	handler := http.Handler(mux)
	handler = withAuditLogging(auditLogs, auditResolver, handler)
	handler = withViewerScope(users, handler)
	handler = withAuth(cfg, apiTokens, sessions, panelSettings, handler)
	handler = withCORS(cfg, handler)
	handler = withRequestLogging(handler)

	return handler
}
