package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/remotesvc"
	"vue-project-backend/internal/store"

	"golang.org/x/sync/singleflight"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string    `json:"token"`
	User  userShape `json:"user"`
}

type userShape struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Name  string `json:"name"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

var serverCreateSingleflight singleflight.Group

const recentServerCreateTTL = 2 * time.Minute

var (
	recentServerCreateMu sync.Mutex
	recentServerCreates  = map[string]recentServerCreateEntry{}
)

type recentServerCreateEntry struct {
	serverID int64
	created  time.Time
}

func serverCreateDedupeKey(payload serverCreatePayload) string {
	ids := append([]int64(nil), payload.UserIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var b strings.Builder
	b.WriteString(strings.ToLower(strings.TrimSpace(payload.Name)))
	b.WriteByte('|')
	b.WriteString(strings.TrimSpace(payload.IP))
	b.WriteByte('|')
	b.WriteString(strings.TrimSpace(payload.SSHUser))
	b.WriteByte('|')
	b.WriteString(strings.TrimSpace(payload.SSHPort))
	b.WriteByte('|')
	b.WriteString(strings.ToLower(strings.TrimSpace(payload.LicenseType)))
	b.WriteByte('|')
	b.WriteString(strings.TrimSpace(payload.LicenseFile))
	b.WriteByte('|')
	b.WriteString(strings.TrimSpace(payload.VersionUUID))
	b.WriteByte('|')
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", id)
	}
	return b.String()
}

func pruneRecentServerCreatesUnlocked() {
	now := time.Now()
	for k, e := range recentServerCreates {
		if now.Sub(e.created) > recentServerCreateTTL {
			delete(recentServerCreates, k)
		}
	}
}

func tryRespondRecentServerCreate(w http.ResponseWriter, r *http.Request, servers store.ServerStore, dedupeKey string) bool {
	recentServerCreateMu.Lock()
	defer recentServerCreateMu.Unlock()
	pruneRecentServerCreatesUnlocked()
	if e, ok := recentServerCreates[dedupeKey]; ok && time.Since(e.created) < 90*time.Second {
		view, err := servers.GetView(r.Context(), e.serverID)
		if err != nil {
			return false
		}
		log.Printf("[api] POST /servers: duplicate POST within 90s; returning existing serverID=%d", e.serverID)
		writeJSON(w, http.StatusCreated, view)
		return true
	}
	return false
}

func rememberRecentServerCreate(dedupeKey string, serverID int64) {
	recentServerCreateMu.Lock()
	defer recentServerCreateMu.Unlock()
	recentServerCreates[dedupeKey] = recentServerCreateEntry{serverID: serverID, created: time.Now()}
	pruneRecentServerCreatesUnlocked()
}

type httpAPIErr struct {
	status  int
	message string
}

func (e *httpAPIErr) Error() string {
	return e.message
}

func apiHTTPError(status int, message string) error {
	return &httpAPIErr{status: status, message: message}
}

// storeLicenseTypeFromDeployResponse maps deploy_license JSON license_type
// (trial | l4 | l7 | unified) back to the dashboard / servers.license_type label
// (Trial | L4 | L7 | Unified).
func storeLicenseTypeFromDeployResponse(deploy deployCreateServerResponse, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(deploy.LicenseType)) {
	case "trial":
		return "Trial"
	case "l4":
		return "L4"
	case "l7":
		return "L7"
	case "unified":
		return "Unified"
	}
	fb := strings.TrimSpace(fallback)
	if fb != "" {
		return fb
	}
	return "Trial"
}

// performServerCreate runs deploy_license then persists the server. opCtx should tolerate client
// disconnect (typically context.WithoutCancel(r.Context())).
func performServerCreate(
	opCtx context.Context,
	cfg config.Config,
	servers store.ServerStore,
	payload serverCreatePayload,
	deployTimeout int,
) (store.ServerView, error) {
	if strings.TrimSpace(payload.VersionUUID) == "" {
		return store.ServerView{}, apiHTTPError(http.StatusBadRequest, "versionUuid is required")
	}
	token, err := generateServerToken()
	if err != nil {
		log.Printf("[api] POST /servers: generate token failed: %v", err)
		return store.ServerView{}, apiHTTPError(http.StatusInternalServerError, "failed to prepare server token")
	}
	deployBaseCtx := context.WithoutCancel(opCtx)
	deployCtx, cancelDeploy := context.WithTimeout(deployBaseCtx, time.Duration(deployTimeout)*time.Second)
	defer cancelDeploy()
	deployResp, err := createDeployLicenseServer(deployCtx, cfg, payload, token)
	if err != nil {
		log.Printf("[api] POST /servers: deploy_license failed: %v", err)
		return store.ServerView{}, apiHTTPError(http.StatusBadGateway, err.Error())
	}
	expireRaw := strings.TrimSpace(deployResp.DeployComplete.ExpireDate)
	if expireRaw == "" {
		expireRaw = strings.TrimSpace(deployResp.ExpireDate)
	}
	expiredAt, err := parseDeployExpireDate(expireRaw)
	if err != nil {
		log.Printf("[api] POST /servers: invalid expire_date from deploy_license raw=%q err=%v",
			expireRaw, err)
		return store.ServerView{}, apiHTTPError(http.StatusBadGateway, "deploy license returned invalid expire_date")
	}
	deployToken := strings.TrimSpace(deployResp.DeployComplete.Token)
	if deployToken == "" {
		deployToken = token
	}
	deployServiceStatus, deployL4Status, deployL7Status := probeRemoteRuntimeStatuses(
		opCtx,
		strings.TrimSpace(payload.IP),
		strings.TrimSpace(payload.SSHUser),
		strings.TrimSpace(payload.SSHPassword),
		strings.TrimSpace(payload.SSHPort),
	)
	rowStatus := strings.TrimSpace(payload.Status)
	if rowStatus == "" {
		rowStatus = "Normal"
	}
	deployVersion := strings.TrimSpace(deployResp.DeployComplete.Version)
	if deployVersion == "" {
		deployVersion = strings.TrimSpace(deployResp.Version)
	}
	deployOS := deployProductOS(deployResp)
	if deployOS == "" {
		deployOS = strings.TrimSpace(payload.OS)
	}
	storedLicenseType := storeLicenseTypeFromDeployResponse(deployResp, payload.LicenseType)
	created, err := servers.Create(opCtx, store.ServerInput{
		Name:           strings.TrimSpace(payload.Name),
		IP:             strings.TrimSpace(payload.IP),
		Status:         rowStatus,
		ServiceStatus:  deployServiceStatus,
		L4Status:       deployL4Status,
		L7Status:       deployL7Status,
		LicenseType:    storedLicenseType,
		LicenseFile:    strings.TrimSpace(payload.LicenseFile),
		Version:        deployVersion,
		OS:             deployOS,
		SSHUser:        strings.TrimSpace(payload.SSHUser),
		SSHPassword:    strings.TrimSpace(payload.SSHPassword),
		SSHPort:        strings.TrimSpace(payload.SSHPort),
		Token:          deployToken,
		Expired:        expiredAt,
	})
	if err != nil {
		log.Printf("[api] POST /servers: DB Create failed: %v", err)
		return store.ServerView{}, apiHTTPError(http.StatusInternalServerError, "failed to create server")
	}
	if err := servers.UpdateServerUsers(opCtx, created.ID, payload.UserIDs); err != nil {
		log.Printf("[api] POST /servers: UpdateServerUsers serverID=%d failed: %v", created.ID, err)
		return store.ServerView{}, apiHTTPError(http.StatusInternalServerError, "failed to assign server users")
	}
	if err := servers.UpdateDeploymentData(
		opCtx,
		created.ID,
		deployToken,
		"",
		storedLicenseType,
		deployVersion,
		deployOS,
		expiredAt,
		deployServiceStatus,
		deployL4Status,
		deployL7Status,
	); err != nil {
		log.Printf("[api] POST /servers: UpdateDeploymentData serverID=%d failed: %v", created.ID, err)
		return store.ServerView{}, apiHTTPError(http.StatusInternalServerError, "failed to persist deployment result")
	}
	view, err := servers.GetView(opCtx, created.ID)
	if err != nil {
		log.Printf("[api] POST /servers: GetView serverID=%d failed: %v", created.ID, err)
		return store.ServerView{}, apiHTTPError(http.StatusInternalServerError, "failed to load server")
	}
	log.Printf("[api] POST /servers: success serverID=%d name=%q ip=%q version=%q angelos=%q l4=%q l7=%q",
		created.ID, view.Name, view.IP, view.Version, deployServiceStatus, deployL4Status, deployL7Status)
	return view, nil
}

func registerRoutes(
	mux *http.ServeMux,
	cfg config.Config,
	agentClient *AgentClient,
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
) {
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/health", healthHandler)
	mux.HandleFunc("/api/v1/status", statusHandler)
	mux.HandleFunc("/report_xdp", reportXdpHandler(securityEvents, servers, blacklist, l4LiveAttack, l4Blacklist))
	mux.HandleFunc("/api/report_xdp", reportXdpHandler(securityEvents, servers, blacklist, l4LiveAttack, l4Blacklist))
	mux.HandleFunc("/dashboard/summary", dashboardSummaryHandler(users, servers, blacklist, l4LiveAttack, serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/summary", dashboardSummaryHandler(users, servers, blacklist, l4LiveAttack, serverTrafficStats))
	mux.HandleFunc("/dashboard/security-events", dashboardSecurityEventsHandler(securityEvents))
	mux.HandleFunc("/api/v1/dashboard/security-events", dashboardSecurityEventsHandler(securityEvents))
	mux.HandleFunc("/dashboard/bandwidth", dashboardBandwidthHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/bandwidth", dashboardBandwidthHandler(serverTrafficStats))
	mux.HandleFunc("/dashboard/bandwidth-nic-rx", dashboardBandwidthNicRxHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/bandwidth-nic-rx", dashboardBandwidthNicRxHandler(serverTrafficStats))
	mux.HandleFunc("/dashboard/bandwidth-nic-tx", dashboardBandwidthNicTxHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/bandwidth-nic-tx", dashboardBandwidthNicTxHandler(serverTrafficStats))
	mux.HandleFunc("/dashboard/bandwidth-l7-rx", dashboardBandwidthL7RxHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/bandwidth-l7-rx", dashboardBandwidthL7RxHandler(serverTrafficStats))
	mux.HandleFunc("/dashboard/bandwidth-l7-tx", dashboardBandwidthL7TxHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/bandwidth-l7-tx", dashboardBandwidthL7TxHandler(serverTrafficStats))
	mux.HandleFunc("/dashboard/request-response", dashboardRequestResponseHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/request-response", dashboardRequestResponseHandler(serverTrafficStats))
	mux.HandleFunc("/dashboard/status-codes", dashboardStatusCodesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/dashboard/status-codes", dashboardStatusCodesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/summary", analyticsSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/summary", analyticsSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/nic-rx-bandwidth", analyticsNicRxBandwidthSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/nic-rx-bandwidth", analyticsNicRxBandwidthSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/nic-tx-bandwidth", analyticsNicTxBandwidthSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/nic-tx-bandwidth", analyticsNicTxBandwidthSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/l7-rx-bandwidth", analyticsL7RxBandwidthSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/l7-rx-bandwidth", analyticsL7RxBandwidthSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/l7-tx-bandwidth", analyticsL7TxBandwidthSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/l7-tx-bandwidth", analyticsL7TxBandwidthSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/nic-rx-traffic", analyticsNicRxTrafficSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/nic-rx-traffic", analyticsNicRxTrafficSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/nic-tx-traffic", analyticsNicTxTrafficSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/nic-tx-traffic", analyticsNicTxTrafficSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/l7-rx-traffic", analyticsL7RxTrafficSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/l7-rx-traffic", analyticsL7RxTrafficSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/l7-tx-traffic", analyticsL7TxTrafficSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/l7-tx-traffic", analyticsL7TxTrafficSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/request-response", analyticsRequestResponseSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/request-response", analyticsRequestResponseSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/status-codes", analyticsStatusCodesSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/status-codes", analyticsStatusCodesSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/ip-count", analyticsIpCountSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/ip-count", analyticsIpCountSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/methods", analyticsMethodSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/methods", analyticsMethodSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/series/protocols", analyticsProtocolSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/series/protocols", analyticsProtocolSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/summary/status-codes", analyticsStatusCodesSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/summary/status-codes", analyticsStatusCodesSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/summary/methods", analyticsMethodSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/summary/methods", analyticsMethodSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/summary/protocols", analyticsProtocolSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/summary/protocols", analyticsProtocolSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/summary/top-ips", analyticsTopIpsSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/summary/top-ips", analyticsTopIpsSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/summary/isps", analyticsIspSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/summary/isps", analyticsIspSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/summary/referers", analyticsRefererSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/summary/referers", analyticsRefererSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/summary/countries", analyticsCountrySummaryHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/summary/countries", analyticsCountrySummaryHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/security/summary", securityAnalyticsSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/security/summary", securityAnalyticsSummaryHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/security/series/block-count", securityAnalyticsBlockedSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/security/series/block-count", securityAnalyticsBlockedSeriesHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/security/summary/countries", securityAnalyticsCountrySummaryHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/security/summary/countries", securityAnalyticsCountrySummaryHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/security/summary/top-requests", securityAnalyticsTopRequestsHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/security/summary/top-requests", securityAnalyticsTopRequestsHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/security/summary/top-blocks", securityAnalyticsTopBlocksHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/security/summary/top-blocks", securityAnalyticsTopBlocksHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/security/summary/top-urls", securityAnalyticsTopUrlsHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/security/summary/top-urls", securityAnalyticsTopUrlsHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/security/summary/top-referers", securityAnalyticsTopReferersHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/security/summary/top-referers", securityAnalyticsTopReferersHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/security/summary/top-user-agents", securityAnalyticsTopUserAgentsHandler(serverTrafficStats))
	mux.HandleFunc("/api/v1/analytics/security/summary/top-user-agents", securityAnalyticsTopUserAgentsHandler(serverTrafficStats))
	mux.HandleFunc("/analytics/l4/summary", l4AnalyticsSummaryHandler(l4AttackStats))
	mux.HandleFunc("/api/v1/analytics/l4/summary", l4AnalyticsSummaryHandler(l4AttackStats))
	mux.HandleFunc("/analytics/l4/series/traffic", l4AnalyticsTrafficSeriesHandler(l4AttackStats))
	mux.HandleFunc("/api/v1/analytics/l4/series/traffic", l4AnalyticsTrafficSeriesHandler(l4AttackStats))
	mux.HandleFunc("/analytics/l4/series/protocols", l4AnalyticsProtocolSeriesHandler(l4AttackStats))
	mux.HandleFunc("/api/v1/analytics/l4/series/protocols", l4AnalyticsProtocolSeriesHandler(l4AttackStats))
	mux.HandleFunc("/analytics/l4/attacks/recent", l4AnalyticsRecentAttacksHandler(l4AttackStats))
	mux.HandleFunc("/api/v1/analytics/l4/attacks/recent", l4AnalyticsRecentAttacksHandler(l4AttackStats))
	mux.HandleFunc("/analytics/l4/attacks/top-ips", l4AnalyticsTopIpsHandler(l4AttackStats))
	mux.HandleFunc("/api/v1/analytics/l4/attacks/top-ips", l4AnalyticsTopIpsHandler(l4AttackStats))
	mux.HandleFunc("/auth/login", loginHandler(users))
	mux.HandleFunc("/api/get_blocklist_ips", getBlocklistIPsHandler(servers, l4Blacklist))
	mux.HandleFunc("/api/v1/get_blocklist_ips", getBlocklistIPsHandler(servers, l4Blacklist))
	mux.HandleFunc("/api/get_whitelist_ips", getWhitelistIPsHandler(servers, l4Whitelist))
	mux.HandleFunc("/api/v1/get_whitelist_ips", getWhitelistIPsHandler(servers, l4Whitelist))
	mux.HandleFunc("/api/v1/deploy-versions", deployLicenseVersionsHandler(cfg))
	mux.HandleFunc("/api/v1/servers/probe-host-versions", probeHostVersionsHandler(cfg))
	mux.HandleFunc("/servers", serversHandler(cfg, servers))
	mux.HandleFunc("/servers/blacklist", serverBlacklistHandler(servers, blacklist))
	mux.HandleFunc("/servers/blacklist/", serverBlacklistHandler(servers, blacklist))
	mux.HandleFunc("/temporary_blacklist_added", temporaryBlacklistAddedHandler(servers, blacklist))
	mux.HandleFunc("/api/temporary_blacklist_added", temporaryBlacklistAddedHandler(servers, blacklist))
	mux.HandleFunc("/api/v1/temporary_blacklist_added", temporaryBlacklistAddedHandler(servers, blacklist))
	mux.HandleFunc("/servers/", serverDetailHandler(cfg, agentClient, servers, l4, l4Whitelist, l4Blacklist, wafWhitelist, wafBlacklist, wafGeo, wafAntiCc, wafAntiHeader, wafInterval, wafSecond, wafResponse, wafUserAgent, upstreamServers, listeningPorts, cacheRules))
	mux.HandleFunc("/users", usersHandler(users))
	mux.HandleFunc("/users/", userHandler(users))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": "v1",
	})
}

type reportXdpPayload struct {
	Token      string `json:"token"`
	Command    string `json:"command"`
	Data       string `json:"data"`
	IP         string `json:"ip"`
	TTL        string `json:"ttl"`
	AttackType string `json:"attack_type"`
}

// getBlocklistIPsPayload is the request shape for /api/get_blocklist_ips.
// It reuses the same authentication model as /report_xdp: identify server by token.
type getBlocklistIPsPayload struct {
	Token string `json:"token"`
}

// getBlocklistIPsHandler exposes a simple API endpoint that returns L4 blacklist
// IPs for the server identified by the provided token. The response is an array
// of objects with fields: ip, reason, created_at.
// Accepts GET with ?token=... or POST with JSON body {"token": "..."}.
func getBlocklistIPsHandler(servers store.ServerStore, l4Blacklist store.L4BlacklistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var token string
		switch r.Method {
		case http.MethodGet:
			token = strings.TrimSpace(r.URL.Query().Get("token"))
		case http.MethodPost:
			var payload getBlocklistIPsPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			token = strings.TrimSpace(payload.Token)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if token == "" {
			writeError(w, http.StatusForbidden, "missing token")
			return
		}

		server, err := servers.GetByToken(r.Context(), token)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusForbidden, "invalid token")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to validate token")
			return
		}

		entries, err := l4Blacklist.ListByServer(r.Context(), server.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l4 blacklist entries")
			return
		}

		type blocklistIP struct {
			IP        string `json:"ip"`
			Reason    string `json:"reason"`
			CreatedAt string `json:"created_at"`
		}

		result := make([]blocklistIP, 0, len(entries))
		for _, e := range entries {
			result = append(result, blocklistIP{
				IP:        strings.TrimSpace(e.IPAddress),
				Reason:    strings.TrimSpace(e.Reason),
				CreatedAt: e.CreatedAt,
			})
		}

		writeJSON(w, http.StatusOK, result)
	}
}

// getWhitelistIPsHandler exposes a simple API endpoint that returns L4 whitelist
// IPs for the server identified by the provided token. The response is an array
// of objects with fields: ip, reason, created_at.
// Accepts GET with ?token=... or POST with JSON body {"token": "..."}.
func getWhitelistIPsHandler(servers store.ServerStore, l4Whitelist store.L4WhitelistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var token string
		switch r.Method {
		case http.MethodGet:
			token = strings.TrimSpace(r.URL.Query().Get("token"))
		case http.MethodPost:
			var payload getBlocklistIPsPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			token = strings.TrimSpace(payload.Token)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if token == "" {
			writeError(w, http.StatusForbidden, "missing token")
			return
		}

		server, err := servers.GetByToken(r.Context(), token)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusForbidden, "invalid token")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to validate token")
			return
		}

		entries, err := l4Whitelist.ListByServer(r.Context(), server.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l4 whitelist entries")
			return
		}

		type whitelistIP struct {
			IP        string `json:"ip"`
			Reason    string `json:"reason"`
			CreatedAt string `json:"created_at"`
		}

		result := make([]whitelistIP, 0, len(entries))
		for _, e := range entries {
			result = append(result, whitelistIP{
				IP:        strings.TrimSpace(e.IPAddress),
				Reason:    strings.TrimSpace(e.Reason),
				CreatedAt: e.CreatedAt,
			})
		}

		writeJSON(w, http.StatusOK, result)
	}
}

func reportXdpHandler(
	securityEvents store.SecurityEventStore,
	servers store.ServerStore,
	blacklist store.BlacklistStore,
	l4LiveAttack store.L4LiveAttackStore,
	l4Blacklist store.L4BlacklistStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var payload reportXdpPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		payload.Command = strings.TrimSpace(payload.Command)
		payload.Token = strings.TrimSpace(payload.Token)
		payload.Data = strings.TrimSpace(payload.Data)
		payload.IP = strings.TrimSpace(payload.IP)
		payload.TTL = strings.TrimSpace(payload.TTL)
		payload.AttackType = strings.TrimSpace(payload.AttackType)

		if payload.Token == "" {
			writeError(w, http.StatusForbidden, "missing token")
			return
		}

		server, err := servers.GetByToken(r.Context(), payload.Token)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusForbidden, "invalid token")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to validate token")
			return
		}

		if strings.EqualFold(payload.Command, "report_block_ip") {
			if payload.IP == "" {
				writeError(w, http.StatusBadRequest, "missing ip")
				return
			}
			//input := buildBlacklistInput(server.Name, payload)
			//if _, err := blacklist.Create(r.Context(), server.ID, input); err != nil {
			//	writeError(w, http.StatusInternalServerError, "failed to store blacklist entry")
			//	return
			//}
			if err := l4LiveAttack.Create(r.Context(), server.ID, payload.IP, payload.AttackType); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to store l4 live attack")
				return
			}
			title, description, ok := buildSecurityEvent(payload)
			if ok {
				if err := securityEvents.Create(r.Context(), title, description); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to store security event")
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		title, description, ok := buildSecurityEvent(payload)
		if !ok {
			writeError(w, http.StatusBadRequest, "unsupported command or data")
			return
		}

		if err := securityEvents.Create(r.Context(), title, description); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to store security event")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func buildSecurityEvent(payload reportXdpPayload) (string, string, bool) {
	command := strings.ToLower(payload.Command)
	data := strings.ToLower(payload.Data)

	switch command {
	case "report_license":
		switch data {
		case "expired":
			return "License issue", "License has expired, please take action.", true
		case "manipulated":
			return "License issue", "License is manually manipulated, please take action.", true
		default:
			if payload.Data == "" {
				return "", "", false
			}
			return "License issue", fmt.Sprintf("License issue reported: %s", payload.Data), true
		}
	case "report_attack":
		switch data {
		case "attack_start":
			return "L4 DDOS Attack", "L4 DDOS Attack has started.", true
		case "attack_stop":
			return "L4 DDOS Attack", "L4 DDOS Attack has stopped.", true
		default:
			if payload.Data == "" {
				return "", "", false
			}
			return "L4 DDOS Attack", fmt.Sprintf("L4 DDOS Attack report: %s", payload.Data), true
		}
	case "report_block_ip":
		if payload.IP == "" {
			return "", "", false
		}
		description := fmt.Sprintf("Multiple packets from IP %s is blocked", payload.IP)
		if payload.TTL != "" {
			description = fmt.Sprintf("%s for %s seconds", description, payload.TTL)
		}
		if payload.AttackType != "" {
			description = fmt.Sprintf("%s due to %s attack", description, payload.AttackType)
		}
		return "DDos Attack Detected", description, true
	case "report_protection":
		if payload.Data == "" {
			return "", "", false
		}
		return "Protection Mode", fmt.Sprintf("Protection event: %s", payload.Data), true
	default:
		return "", "", false
	}
}

func buildBlacklistInput(serverName string, payload reportXdpPayload) store.BlacklistInput {
	reason := "Reported by agent"
	if payload.AttackType != "" {
		reason = payload.AttackType
	}
	return store.BlacklistInput{
		IPAddress:   payload.IP,
		Reason:      reason,
		URL:         "",
		Server:      serverName,
		TTL:         payload.TTL,
		TriggerRule: payload.AttackType,
	}
}

type dashboardSummaryResponse struct {
	TotalUsers             int64 `json:"totalUsers"`
	TotalServers           int64 `json:"totalServers"`
	ActiveServers          int64 `json:"activeServers"`
	BlockedIps             int64 `json:"blockedIps"`
	L4AttacksThisMonth     int64 `json:"l4AttacksThisMonth"`
	L4AttacksPreviousMonth int64 `json:"l4AttacksPreviousMonth"`
	L7ThreatsThisMonth     int64 `json:"l7ThreatsThisMonth"`
	L7ThreatsPreviousMonth int64 `json:"l7ThreatsPreviousMonth"`
}

func dashboardSummaryHandler(users store.UserStore, servers store.ServerStore, blacklist store.BlacklistStore, l4LiveAttack store.L4LiveAttackStore, trafficStats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		totalUsers, err := users.Count(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load users total")
			return
		}

		totalServers, err := servers.Count(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load servers total")
			return
		}

		activeServers, err := servers.CountByStatus(r.Context(), "Normal")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load active servers")
			return
		}

		blockedIps, err := blacklist.Count(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load blocked ips")
			return
		}

		now := time.Now()
		startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		startOfNextMonth := startOfMonth.AddDate(0, 1, 0)
		startOfPreviousMonth := startOfMonth.AddDate(0, -1, 0)

		l4ThisMonth, err := l4LiveAttack.CountBetween(r.Context(), startOfMonth, startOfNextMonth)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l4 attacks this month")
			return
		}

		l4PreviousMonth, err := l4LiveAttack.CountBetween(r.Context(), startOfPreviousMonth, startOfMonth)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l4 attacks previous month")
			return
		}

		l7ThisMonth, err := trafficStats.SumBlockedRequests(r.Context(), startOfMonth, startOfNextMonth)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l7 threats this month")
			return
		}

		l7PreviousMonth, err := trafficStats.SumBlockedRequests(r.Context(), startOfPreviousMonth, startOfMonth)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l7 threats previous month")
			return
		}

		writeJSON(w, http.StatusOK, dashboardSummaryResponse{
			TotalUsers:             totalUsers,
			TotalServers:           totalServers,
			ActiveServers:          activeServers,
			BlockedIps:             blockedIps,
			L4AttacksThisMonth:     l4ThisMonth,
			L4AttacksPreviousMonth: l4PreviousMonth,
			L7ThreatsThisMonth:     l7ThisMonth,
			L7ThreatsPreviousMonth: l7PreviousMonth,
		})
	}
}

func dashboardSecurityEventsHandler(securityEvents store.SecurityEventStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		limit := 5
		if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
			if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		events, err := securityEvents.ListRecent(r.Context(), limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load security events")
			return
		}

		writeJSON(w, http.StatusOK, events)
	}
}

type bandwidthPoint struct {
	Timestamp string `json:"timestamp"`
	Bandwidth int64  `json:"bandwidth"`
}

type bandwidthSeries struct {
	ServerID int64            `json:"serverId"`
	Points   []bandwidthPoint `json:"points"`
}

func dashboardBandwidthHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return dashboardBandwidthByServerHandler(stats, stats.ListBandwidth)
}

func dashboardBandwidthNicRxHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return dashboardBandwidthByServerHandler(stats, stats.ListNicRxBandwidthByServer)
}

func dashboardBandwidthNicTxHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return dashboardBandwidthByServerHandler(stats, stats.ListNicTxBandwidthByServer)
}

func dashboardBandwidthL7RxHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return dashboardBandwidthByServerHandler(stats, stats.ListL7RxBandwidthByServer)
}

func dashboardBandwidthL7TxHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return dashboardBandwidthByServerHandler(stats, stats.ListL7TxBandwidthByServer)
}

type bandwidthByServerFunc func(context.Context, time.Time, time.Time, int64) ([]store.ServerBandwidthPoint, error)

func dashboardBandwidthByServerHandler(stats store.ServerTrafficStatsStore, listFn bandwidthByServerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		rangeValue := parseBandwidthRange(r.URL.Query().Get("range"))

		var serverID int64
		if rawServerID := strings.TrimSpace(r.URL.Query().Get("serverId")); rawServerID != "" {
			parsed, err := strconv.ParseInt(rawServerID, 10, 64)
			if err != nil || parsed < 0 {
				writeError(w, http.StatusBadRequest, "invalid serverId")
				return
			}
			serverID = parsed
		}

		end := time.Now()
		start := end.Add(-rangeValue)

		points, err := listFn(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load bandwidth stats")
			return
		}

		grouped := make(map[int64][]bandwidthPoint)
		for _, point := range points {
			grouped[point.ServerID] = append(grouped[point.ServerID], bandwidthPoint{
				Timestamp: point.Timestamp,
				Bandwidth: point.Bandwidth,
			})
		}

		serverIDs := make([]int64, 0, len(grouped))
		for id := range grouped {
			serverIDs = append(serverIDs, id)
		}
		sort.Slice(serverIDs, func(i, j int) bool { return serverIDs[i] < serverIDs[j] })

		series := make([]bandwidthSeries, 0, len(serverIDs))
		for _, id := range serverIDs {
			series = append(series, bandwidthSeries{
				ServerID: id,
				Points:   grouped[id],
			})
		}

		writeJSON(w, http.StatusOK, series)
	}
}

func dashboardRequestResponseHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		rangeValue := parseTrafficRange(r.URL.Query().Get("range"))
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		end := time.Now()
		start := end.Add(-rangeValue)

		points, err := stats.ListRequestResponse(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load request response stats")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func dashboardStatusCodesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		rangeValue := parseTrafficRange(r.URL.Query().Get("range"))
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		end := time.Now()
		start := end.Add(-rangeValue)

		points, err := stats.ListStatusCodes(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load status code stats")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func parseBandwidthRange(value string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "30m":
		return 30 * time.Minute
	case "1h":
		return time.Hour
	case "2h":
		return 2 * time.Hour
	case "4h":
		return 4 * time.Hour
	case "8h":
		return 8 * time.Hour
	case "12h":
		return 12 * time.Hour
	case "24h":
		return 24 * time.Hour
	case "48h":
		return 48 * time.Hour
	default:
		return 30 * time.Minute
	}
}

func parseTrafficRange(value string) time.Duration {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return 30 * time.Minute
	}
	if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil && parsed > 0 {
		return time.Duration(parsed) * time.Millisecond
	}
	if strings.HasSuffix(trimmed, "m") {
		if minutes, err := strconv.ParseInt(strings.TrimSuffix(trimmed, "m"), 10, 64); err == nil && minutes > 0 {
			return time.Duration(minutes) * time.Minute
		}
	}
	if strings.HasSuffix(trimmed, "h") {
		if hours, err := strconv.ParseInt(strings.TrimSuffix(trimmed, "h"), 10, 64); err == nil && hours > 0 {
			return time.Duration(hours) * time.Hour
		}
	}
	return 30 * time.Minute
}

func parseServerIDParam(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || parsed < 0 {
		return 0, err
	}
	return parsed, nil
}

type analyticsSummaryResponse struct {
	TotalNicRxTraffic      int64  `json:"totalNicRxTraffic"`
	TotalNicTxTraffic      int64  `json:"totalNicTxTraffic"`
	TotalL7RxTraffic       int64  `json:"totalL7RxTraffic"`
	TotalL7TxTraffic       int64  `json:"totalL7TxTraffic"`
	NicRxBandwidthLast     int64  `json:"nicRxBandwidthLast"`
	NicRxBandwidthLastTime string `json:"nicRxBandwidthLastTime"`
	NicTxBandwidthLast     int64  `json:"nicTxBandwidthLast"`
	NicTxBandwidthLastTime string `json:"nicTxBandwidthLastTime"`
	L7RxBandwidthLast      int64  `json:"l7RxBandwidthLast"`
	L7RxBandwidthLastTime  string `json:"l7RxBandwidthLastTime"`
	L7TxBandwidthLast      int64  `json:"l7TxBandwidthLast"`
	L7TxBandwidthLastTime  string `json:"l7TxBandwidthLastTime"`
	TotalRequest           int64  `json:"totalRequest"`
	TotalResponse          int64  `json:"totalResponse"`
	IpCount                int64  `json:"ipCount"`
	RefererCount           int64  `json:"refererCount"`
	IspCount               int64  `json:"ispCount"`
}

func analyticsSummaryHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		totalNicRxTraffic, totalNicTxTraffic, totalL7RxTraffic, totalL7TxTraffic, totalRequest, totalResponse, err := stats.SumTotals(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load analytics summary")
			return
		}

		nicRxBandwidthLast, nicRxBandwidthLastTime, err := stats.LatestNicRxBandwidth(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load nic rx bandwidth")
			return
		}

		nicTxBandwidthLast, nicTxBandwidthLastTime, err := stats.LatestNicTxBandwidth(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load nic tx bandwidth")
			return
		}

		l7RxBandwidthLast, l7RxBandwidthLastTime, err := stats.LatestL7RxBandwidth(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l7 rx bandwidth")
			return
		}

		l7TxBandwidthLast, l7TxBandwidthLastTime, err := stats.LatestL7TxBandwidth(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l7 tx bandwidth")
			return
		}

		totalIp, err := stats.SumIPCountStats(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load ip count")
			return
		}

		refererCount, err := stats.SumRefererRequests(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load referer count")
			return
		}

		ispCount, err := stats.SumIspRequests(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load isp count")
			return
		}

		writeJSON(w, http.StatusOK, analyticsSummaryResponse{
			TotalNicRxTraffic:      totalNicRxTraffic,
			TotalNicTxTraffic:      totalNicTxTraffic,
			TotalL7RxTraffic:       totalL7RxTraffic,
			TotalL7TxTraffic:       totalL7TxTraffic,
			NicRxBandwidthLast:     nicRxBandwidthLast,
			NicRxBandwidthLastTime: nicRxBandwidthLastTime.Format(time.RFC3339),
			NicTxBandwidthLast:     nicTxBandwidthLast,
			NicTxBandwidthLastTime: nicTxBandwidthLastTime.Format(time.RFC3339),
			L7RxBandwidthLast:      l7RxBandwidthLast,
			L7RxBandwidthLastTime:  l7RxBandwidthLastTime.Format(time.RFC3339),
			L7TxBandwidthLast:      l7TxBandwidthLast,
			L7TxBandwidthLastTime:  l7TxBandwidthLastTime.Format(time.RFC3339),
			TotalRequest:           totalRequest,
			TotalResponse:          totalResponse,
			IpCount:                totalIp,
			RefererCount:           refererCount,
			IspCount:               ispCount,
		})
	}
}

func analyticsNicRxBandwidthSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListNicRxBandwidthAggregate(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load nic rx bandwidth series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsNicTxBandwidthSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListNicTxBandwidthAggregate(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load nic tx bandwidth series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsL7RxBandwidthSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListL7RxBandwidthAggregate(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l7 rx bandwidth series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsL7TxBandwidthSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListL7TxBandwidthAggregate(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l7 tx bandwidth series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsNicTxTrafficSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListNicTxTraffic(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load traffic series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsNicRxTrafficSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListNicRxTraffic(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load nic rx traffic series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsL7TxTrafficSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListL7TxTraffic(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load traffic series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsL7RxTrafficSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListL7RxTraffic(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load nic rx traffic series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsRequestResponseSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListRequestResponse(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load request response series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsStatusCodesSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListStatusCodes(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load status code series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsIpCountSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListIpCount(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load ip count series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsMethodSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListMethodSeries(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load method series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsProtocolSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListProtocolSeries(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load protocol series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func analyticsStatusCodesSummaryHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		summary, err := stats.SumStatusCodes(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load status code summary")
			return
		}

		writeJSON(w, http.StatusOK, summary)
	}
}

func analyticsMethodSummaryHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		summary, err := stats.SumMethods(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load method summary")
			return
		}

		writeJSON(w, http.StatusOK, summary)
	}
}

func analyticsProtocolSummaryHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		summary, err := stats.SumProtocols(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load protocol summary")
			return
		}

		writeJSON(w, http.StatusOK, summary)
	}
}

func analyticsTopIpsSummaryHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		limit := 10
		if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
			if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		rows, err := stats.ListTopIPs(r.Context(), start, end, serverID, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load top ips")
			return
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

func analyticsIspSummaryHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		limit := 10
		if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
			if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		rows, err := stats.ListTopIsps(r.Context(), start, end, serverID, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load isp summary")
			return
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

func analyticsRefererSummaryHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		limit := 10
		if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
			if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		rows, err := stats.ListTopReferers(r.Context(), start, end, serverID, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load referer summary")
			return
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

func analyticsCountrySummaryHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		rows, err := stats.ListCountryRequests(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load country requests")
			return
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

type securityAnalyticsSummaryResponse struct {
	TotalRequestCounts int64 `json:"totalRequestCounts"`
	BlockRequestCounts int64 `json:"blockRequestCounts"`
	TotalIps           int64 `json:"totalIps"`
	BlacklistedIps     int64 `json:"blacklistedIps"`
}

type securityCountryRow struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type securityAreaRow struct {
	Area  string `json:"area"`
	Count int64  `json:"count"`
}

type securityUrlRow struct {
	URL   string `json:"url"`
	Count int64  `json:"count"`
}

type securityRefererRow struct {
	Referer string `json:"referer"`
	Count   int64  `json:"count"`
}

type securityAgentRow struct {
	Agent string `json:"agent"`
	Count int64  `json:"count"`
}

func securityAnalyticsSummaryHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		totalRequest, blockedRequest, totalIp, blockedIp, err := stats.SumSecurityTotals(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load security analytics summary")
			return
		}

		writeJSON(w, http.StatusOK, securityAnalyticsSummaryResponse{
			TotalRequestCounts: totalRequest,
			BlockRequestCounts: blockedRequest,
			TotalIps:           totalIp,
			BlacklistedIps:     blockedIp,
		})
	}
}

func securityAnalyticsBlockedSeriesHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListBlockedRequestSeries(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load block count series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func securityAnalyticsCountrySummaryHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		rows, err := stats.ListCountryRequests(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load country requests")
			return
		}

		out := make([]securityCountryRow, 0, len(rows))
		for _, row := range rows {
			code := strings.ToUpper(strings.TrimSpace(row.CountryCode))
			out = append(out, securityCountryRow{
				Code:  code,
				Name:  code,
				Count: row.Requests,
			})
		}

		writeJSON(w, http.StatusOK, out)
	}
}

func securityAnalyticsTopRequestsHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		rows, err := stats.ListCountryRequestsByRequests(r.Context(), start, end, serverID, 30)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load top requests")
			return
		}

		out := make([]securityAreaRow, 0, len(rows))
		for _, row := range rows {
			out = append(out, securityAreaRow{
				Area:  strings.ToUpper(strings.TrimSpace(row.CountryCode)),
				Count: row.Requests,
			})
		}

		writeJSON(w, http.StatusOK, out)
	}
}

func securityAnalyticsTopBlocksHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		rows, err := stats.ListCountryRequestsByBlocked(r.Context(), start, end, serverID, 30)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load top blocks")
			return
		}

		out := make([]securityAreaRow, 0, len(rows))
		for _, row := range rows {
			out = append(out, securityAreaRow{
				Area:  strings.ToUpper(strings.TrimSpace(row.CountryCode)),
				Count: row.Blocked,
			})
		}

		writeJSON(w, http.StatusOK, out)
	}
}

func securityAnalyticsTopUrlsHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		rows, err := stats.ListTopUrls(r.Context(), start, end, serverID, 10)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load top urls")
			return
		}

		out := make([]securityUrlRow, 0, len(rows))
		for _, row := range rows {
			out = append(out, securityUrlRow{
				URL:   row.URL,
				Count: row.Requests,
			})
		}

		writeJSON(w, http.StatusOK, out)
	}
}

func securityAnalyticsTopReferersHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		rows, err := stats.ListTopReferers(r.Context(), start, end, serverID, 10)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load top referers")
			return
		}

		out := make([]securityRefererRow, 0, len(rows))
		for _, row := range rows {
			out = append(out, securityRefererRow{
				Referer: row.Referer,
				Count:   row.Requests,
			})
		}

		writeJSON(w, http.StatusOK, out)
	}
}

func securityAnalyticsTopUserAgentsHandler(stats store.ServerTrafficStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		rows, err := stats.ListTopUserAgents(r.Context(), start, end, serverID, 10)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load top user agents")
			return
		}

		out := make([]securityAgentRow, 0, len(rows))
		for _, row := range rows {
			out = append(out, securityAgentRow{
				Agent: row.Agent,
				Count: row.Requests,
			})
		}

		writeJSON(w, http.StatusOK, out)
	}
}

type l4SummaryResponse struct {
	TotalTraffic   int64 `json:"totalTraffic"`
	AllowedTraffic int64 `json:"allowedTraffic"`
	BlockedTraffic int64 `json:"blockedTraffic"`
}

func l4AnalyticsSummaryHandler(stats store.L4AttackStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		total, allowed, blocked, err := stats.SumTrafficTotals(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l4 summary")
			return
		}

		writeJSON(w, http.StatusOK, l4SummaryResponse{
			TotalTraffic:   total,
			AllowedTraffic: allowed,
			BlockedTraffic: blocked,
		})
	}
}

func l4AnalyticsTrafficSeriesHandler(stats store.L4AttackStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListTrafficSeries(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l4 traffic series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func l4AnalyticsProtocolSeriesHandler(stats store.L4AttackStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		points, err := stats.ListProtocolSeries(r.Context(), start, end, serverID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load l4 protocol series")
			return
		}

		writeJSON(w, http.StatusOK, points)
	}
}

func l4AnalyticsRecentAttacksHandler(stats store.L4AttackStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		limit := 10
		if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
			if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		rows, err := stats.ListRecentAttacks(r.Context(), start, end, serverID, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load recent attacks")
			return
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

func l4AnalyticsTopIpsHandler(stats store.L4AttackStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		start, end, err := parseAnalyticsWindow(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid time range")
			return
		}
		serverID, err := parseServerIDParam(r.URL.Query().Get("serverId"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serverId")
			return
		}

		limit := 10
		if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
			if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		rows, err := stats.ListTopAttackIPs(r.Context(), start, end, serverID, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load top ips")
			return
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

func parseAnalyticsWindow(r *http.Request) (time.Time, time.Time, error) {
	query := r.URL.Query()
	if startRaw := strings.TrimSpace(query.Get("start")); startRaw != "" || strings.TrimSpace(query.Get("end")) != "" {
		start, err := parseTimeValue(startRaw)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		end, err := parseTimeValue(strings.TrimSpace(query.Get("end")))
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		if end.Before(start) {
			return time.Time{}, time.Time{}, errors.New("end before start")
		}
		return start, end, nil
	}

	rangeValue := strings.ToLower(strings.TrimSpace(query.Get("range")))
	now := time.Now()
	switch rangeValue {
	case "today":
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		return start, start.Add(24 * time.Hour), nil
	case "yesterday":
		end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		return end.Add(-24 * time.Hour), end, nil
	}

	duration := parseTrafficRange(rangeValue)
	return now.Add(-duration), now, nil
}

func parseTimeValue(value string) (time.Time, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, errors.New("missing time value")
	}
	if parsed, err := time.Parse(time.RFC3339, trimmed); err == nil {
		return parsed, nil
	}
	if parsed, err := time.ParseInLocation("2006-01-02T15:04", trimmed, time.Local); err == nil {
		return parsed, nil
	}
	if parsed, err := time.ParseInLocation("2006-01-02 15:04:05", trimmed, time.Local); err == nil {
		return parsed, nil
	}
	return time.Time{}, errors.New("invalid time format")
}

func loginHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var payload loginRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		email := strings.ToLower(strings.TrimSpace(payload.Email))
		password := strings.TrimSpace(payload.Password)
		if email == "" || password == "" {
			writeError(w, http.StatusBadRequest, "email and password are required")
			return
		}

		user, err := users.FindByCredentials(r.Context(), email, password)
		if err != nil {
			if store.IsNotFound(err) {
				writeJSON(w, http.StatusUnauthorized, errorResponse{
					Error:   "unauthorized",
					Message: "Invalid email or password. Please try again.",
				})
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to authenticate")
			return
		}

		if strings.EqualFold(user.Status, "Block") {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:   "forbidden",
				Message: "Your account is blocked. Please contact an administrator.",
			})
			return
		}

		if strings.EqualFold(user.Status, "Waiting") {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:   "forbidden",
				Message: "Please wait while admin accept your login.",
			})
			return
		}

		writeJSON(w, http.StatusOK, loginResponse{
			Token: "mock-token",
			User:  userShape{ID: user.ID, Email: user.Email, Role: user.Role, Name: user.Name},
		})
	}
}

func serversHandler(cfg config.Config, servers store.ServerStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			list, err := servers.ListWithUsers(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load servers")
				return
			}
			writeJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var payload serverCreatePayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				log.Printf("[api] POST /servers: invalid JSON: %v", err)
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			deployTimeout := cfg.DeployLicenseTimeoutSeconds
			if deployTimeout <= 0 {
				deployTimeout = 900
			}
			log.Printf("[api] POST /servers: begin name=%q ip=%q licenseType=%q sshUser=%q sshPort=%q userIds=%d licenseFileLen=%d deploy_license_client_timeout=%ds",
				strings.TrimSpace(payload.Name),
				strings.TrimSpace(payload.IP),
				strings.TrimSpace(payload.LicenseType),
				strings.TrimSpace(payload.SSHUser),
				strings.TrimSpace(payload.SSHPort),
				len(payload.UserIDs),
				len(strings.TrimSpace(payload.LicenseFile)),
				deployTimeout,
			)
			dedupeKey := serverCreateDedupeKey(payload)
			if tryRespondRecentServerCreate(w, r, servers, dedupeKey) {
				return
			}

			opCtx := context.WithoutCancel(r.Context())
			idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
			if len(idemKey) > 128 {
				idemKey = idemKey[:128]
			}
			if idemKey != "" {
				log.Printf("[api] POST /servers: Idempotency-Key=%q dedupe_fingerprint_len=%d", idemKey, len(dedupeKey))
			}

			sfKey := "sf:" + dedupeKey
			if len(sfKey) > 512 {
				sfKey = sfKey[:512]
			}

			run := func() (store.ServerView, error) {
				return performServerCreate(opCtx, cfg, servers, payload, deployTimeout)
			}

			var view store.ServerView
			v, err, _ := serverCreateSingleflight.Do(sfKey, func() (interface{}, error) {
				view0, err0 := run()
				if err0 != nil {
					return nil, err0
				}
				return view0, nil
			})
			var execErr error
			if err != nil {
				execErr = err
			} else {
				var ok bool
				view, ok = v.(store.ServerView)
				if !ok {
					execErr = fmt.Errorf("unexpected create response type %T", v)
				}
			}

			if execErr != nil {
				var he *httpAPIErr
				if errors.As(execErr, &he) {
					writeError(w, he.status, he.message)
					return
				}
				writeError(w, http.StatusInternalServerError, execErr.Error())
				return
			}
			rememberRecentServerCreate(dedupeKey, view.ID)
			writeJSON(w, http.StatusCreated, view)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

type serverUsersPayload struct {
	UserIDs []int64 `json:"userIds"`
}

type serverCreatePayload struct {
	Name          string  `json:"name"`
	IP            string  `json:"ip"`
	Status        string  `json:"status"`
	LicenseType   string  `json:"licenseType"`
	LicenseFile   string  `json:"licenseFile"`
	Version       string  `json:"version"`
	VersionUUID   string  `json:"versionUuid"`
	OS            string  `json:"os"`
	SSHUser       string  `json:"sshUser"`
	SSHPassword   string  `json:"sshPassword"`
	SSHPort       string  `json:"sshPort"`
	UserIDs       []int64 `json:"userIds"`
}

type deployCreateServerRequest struct {
	Name          string `json:"name"`
	IP            string `json:"ip"`
	User          string `json:"user"`
	Pass          string `json:"pass"`
	SSHPort       string `json:"ssh_port"`
	LicenseType   string `json:"license_type"`
	LicenseString string `json:"license_string,omitempty"`
	Token         string `json:"token"`
	VersionUUID   string `json:"version_uuid,omitempty"`
}

type deployDorianVersion struct {
	Version  string `json:"version"`
	OS       string `json:"os"`
	FullName string `json:"full_name"`
	UUID     string `json:"uuid"`
}

type deployCreateServerResponse struct {
	Description    string                 `json:"description"`
	LicenseType    string                 `json:"license_type"`
	Version        string                 `json:"version"`
	OS             string                 `json:"os"`
	ExpireDate     string                 `json:"expire_date"`
	ServerStatus   string                 `json:"server_status"`
	L4Status       string                 `json:"l4_status"`
	L7Status       string                 `json:"l7_status"`
	DorianVersion  deployDorianVersion    `json:"dorian_version"`
	DeployComplete deployCompleteResponse `json:"deploy_complete"`
}

func deployProductOS(resp deployCreateServerResponse) string {
	if os := strings.TrimSpace(resp.OS); os != "" {
		return os
	}
	if os := strings.TrimSpace(resp.DorianVersion.OS); os != "" {
		return os
	}
	return ""
}

// normalizeDeployLicenseCreateResponse copies root-level fields from deploy_license
// into deploy_complete when the nested object is empty (flat vs nested JSON).
func normalizeDeployLicenseCreateResponse(d *deployCreateServerResponse) {
	dc := &d.DeployComplete
	if strings.TrimSpace(dc.Version) == "" {
		dc.Version = strings.TrimSpace(d.Version)
	}
	if strings.TrimSpace(dc.ExpireDate) == "" {
		dc.ExpireDate = strings.TrimSpace(d.ExpireDate)
	}
	if strings.TrimSpace(dc.ServerStatus) == "" {
		dc.ServerStatus = strings.TrimSpace(d.ServerStatus)
	}
	if strings.TrimSpace(dc.L4Status) == "" {
		dc.L4Status = strings.TrimSpace(d.L4Status)
	}
	if strings.TrimSpace(dc.L7Status) == "" {
		dc.L7Status = strings.TrimSpace(d.L7Status)
	}
}

// deployLicenseServiceLicenseType maps dashboard license labels
// (Trial | L4 | L7 | Unified) to deploy_license /create_server values
// (trial | l4 | l7 | unified). Comparison is case-insensitive.
//
// Legacy labels ("Enterprise" / "Professional" / "paid") that may still arrive
// from older clients are best-effort mapped to "unified" so deployments do not
// hard-fail during the transition.
func deployLicenseServiceLicenseType(licenseType string) string {
	switch strings.ToLower(strings.TrimSpace(licenseType)) {
	case "trial":
		return "trial"
	case "l4":
		return "l4"
	case "l7":
		return "l7"
	case "unified":
		return "unified"
	case "enterprise", "professional", "paid":
		return "unified"
	default:
		return strings.ToLower(strings.TrimSpace(licenseType))
	}
}

type deployCompleteResponse struct {
	Status       string `json:"status"`
	IP           string `json:"ip"`
	MachineID    string `json:"machine_id"`
	Token        string `json:"token"`
	Version      string `json:"version"`
	ExpireDate   string `json:"expire_date"`
	ServerStatus string `json:"server_status"`
	L4Status     string `json:"l4_status"`
	L7Status     string `json:"l7_status"`
}

func generateServerToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func createDeployLicenseServer(ctx context.Context, cfg config.Config, payload serverCreatePayload, token string) (deployCreateServerResponse, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.DeployLicenseBaseURL), "/")
	if baseURL == "" {
		logDeployLicenseClientf("abort: DEPLOY_LICENSE_BASE_URL is empty")
		return deployCreateServerResponse{}, errors.New("deploy license base url is not configured")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		logDeployLicenseClientf("abort: invalid base URL host parse err=%v", err)
		return deployCreateServerResponse{}, errors.New("deploy license base url is invalid")
	}

	reqPayload := deployCreateServerRequest{
		Name:          strings.TrimSpace(payload.Name),
		IP:            strings.TrimSpace(payload.IP),
		User:          strings.TrimSpace(payload.SSHUser),
		Pass:          strings.TrimSpace(payload.SSHPassword),
		SSHPort:       strings.TrimSpace(payload.SSHPort),
		LicenseType:   deployLicenseServiceLicenseType(payload.LicenseType),
		LicenseString: strings.TrimSpace(payload.LicenseFile),
		Token:         token,
		VersionUUID:   strings.TrimSpace(payload.VersionUUID),
	}
	body, err := json.Marshal(reqPayload)
	if err != nil {
		logDeployLicenseClientf("encode request JSON failed: %v", err)
		return deployCreateServerResponse{}, fmt.Errorf("encode deploy request: %w", err)
	}

	timeout := cfg.DeployLicenseTimeoutSeconds
	if timeout <= 0 {
		timeout = 900
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	target := baseURL + "/create_server"
	logDeployLicenseClientf("POST %s timeout=%ds jsonBytes=%d name=%q ip=%q sshUser=%q sshPort=%q license_type=%q license_string_len=%d token_prefix=%.6s…",
		target, timeout, len(body),
		reqPayload.Name, reqPayload.IP, reqPayload.User, reqPayload.SSHPort,
		reqPayload.LicenseType, len(reqPayload.LicenseString), token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		logDeployLicenseClientf("build request failed: %v", err)
		return deployCreateServerResponse{}, fmt.Errorf("build deploy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logDeployLicenseClientf("HTTP Do error: %v", err)
		return deployCreateServerResponse{}, fmt.Errorf("deploy create_server call failed: %w", err)
	}
	defer resp.Body.Close()

	limitedBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		logDeployLicenseClientf("read body error: %v status=%d", readErr, resp.StatusCode)
		return deployCreateServerResponse{}, fmt.Errorf("read deploy response: %w", readErr)
	}
	bodyPreview := oneLineLogPreview(string(limitedBody), 480)
	logDeployLicenseClientf("response status=%d bodyBytes=%d preview=%q",
		resp.StatusCode, len(limitedBody), bodyPreview)
	if resp.StatusCode != http.StatusOK {
		return deployCreateServerResponse{}, fmt.Errorf("deploy create_server failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(limitedBody)))
	}

	var decoded deployCreateServerResponse
	if err := json.Unmarshal(limitedBody, &decoded); err != nil {
		logDeployLicenseClientf("JSON decode failed: %v preview=%q", err, bodyPreview)
		return deployCreateServerResponse{}, fmt.Errorf("decode deploy response: %w", err)
	}
	normalizeDeployLicenseCreateResponse(&decoded)
	logDeployLicenseClientf("decoded OK description_len=%d root_license_type=%q root_version=%q root_server_status=%q root_l4_status=%q root_l7_status=%q",
		len(decoded.Description),
		strings.TrimSpace(decoded.LicenseType),
		strings.TrimSpace(decoded.Version),
		strings.TrimSpace(decoded.ServerStatus),
		strings.TrimSpace(decoded.L4Status),
		strings.TrimSpace(decoded.L7Status),
	)
	return decoded, nil
}

type deployLicenseVersionItem struct {
	UUID     string  `json:"uuid"`
	Version  string  `json:"version"`
	OS       *string `json:"os"`
	FullName string  `json:"full_name"`
	Path     string  `json:"path,omitempty"`
	Updated  any     `json:"updated,omitempty"`
}

type deployLicenseVersionsEnvelope struct {
	Versions []deployLicenseVersionItem `json:"versions"`
}

func fetchDeployLicenseVersions(ctx context.Context, cfg config.Config) (deployLicenseVersionsEnvelope, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.DeployLicenseBaseURL), "/")
	if baseURL == "" {
		logDeployLicenseClientf("abort: DEPLOY_LICENSE_BASE_URL is empty (get_versions)")
		return deployLicenseVersionsEnvelope{}, errors.New("deploy license base url is not configured")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		logDeployLicenseClientf("abort: invalid base URL (get_versions) err=%v", err)
		return deployLicenseVersionsEnvelope{}, errors.New("deploy license base url is invalid")
	}
	timeout := cfg.DeployLicenseTimeoutSeconds
	if timeout <= 0 {
		timeout = 900
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	target := baseURL + "/get_versions"
	logDeployLicenseClientf("GET %s timeout=%ds", target, timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return deployLicenseVersionsEnvelope{}, fmt.Errorf("build get_versions request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		logDeployLicenseClientf("get_versions HTTP error: %v", err)
		return deployLicenseVersionsEnvelope{}, fmt.Errorf("get_versions request failed: %w", err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return deployLicenseVersionsEnvelope{}, fmt.Errorf("read get_versions response: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		logDeployLicenseClientf("get_versions status=%d body=%q", resp.StatusCode, oneLineLogPreview(string(body), 400))
		return deployLicenseVersionsEnvelope{}, fmt.Errorf("get_versions failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var decoded deployLicenseVersionsEnvelope
	if err := json.Unmarshal(body, &decoded); err != nil {
		logDeployLicenseClientf("get_versions JSON decode failed: %v", err)
		return deployLicenseVersionsEnvelope{}, fmt.Errorf("decode get_versions response: %w", err)
	}
	logDeployLicenseClientf("get_versions OK count=%d", len(decoded.Versions))
	return decoded, nil
}

func deployLicenseVersionsHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		out, err := fetchDeployLicenseVersions(r.Context(), cfg)
		if err != nil {
			log.Printf("[api] GET /api/v1/deploy-versions: %v", err)
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

type probeHostVersionsRequest struct {
	IP          string `json:"ip"`
	SSHUser     string `json:"sshUser"`
	SSHPassword string `json:"sshPassword"`
	SSHPort     string `json:"sshPort"`
}

type probeHostVersionsResponse struct {
	OS       string                     `json:"os"`
	Versions []deployLicenseVersionItem `json:"versions"`
}

func filterDeployVersionsForHostOS(versions []deployLicenseVersionItem, hostOS string) []deployLicenseVersionItem {
	target := remotesvc.NormalizeHostOS(hostOS)
	if target == "" {
		return nil
	}
	out := make([]deployLicenseVersionItem, 0, len(versions))
	for _, item := range versions {
		itemOS := ""
		if item.OS != nil {
			itemOS = remotesvc.NormalizeHostOS(*item.OS)
		}
		if itemOS == target {
			out = append(out, item)
		}
	}
	return out
}

func probeHostVersionsHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var payload probeHostVersionsRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		ip := strings.TrimSpace(payload.IP)
		sshUser := strings.TrimSpace(payload.SSHUser)
		sshPass := strings.TrimSpace(payload.SSHPassword)
		sshPort := strings.TrimSpace(payload.SSHPort)
		if ip == "" || sshUser == "" || sshPass == "" {
			writeError(w, http.StatusBadRequest, "ip, sshUser, and sshPassword are required")
			return
		}

		probeCtx, cancelProbe := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancelProbe()
		hostOS, err := remotesvc.DetectHostOS(probeCtx, remotesvc.SSHTarget{
			Host:     ip,
			User:     sshUser,
			Password: sshPass,
			Port:     sshPort,
		})
		if err != nil {
			log.Printf("[api] POST /api/v1/servers/probe-host-versions: detect os failed ip=%q sshUser=%q: %v",
				ip, sshUser, err)
			writeError(w, http.StatusBadGateway, fmt.Sprintf("failed to detect host OS: %v", err))
			return
		}

		catalog, err := fetchDeployLicenseVersions(r.Context(), cfg)
		if err != nil {
			log.Printf("[api] POST /api/v1/servers/probe-host-versions: get_versions failed: %v", err)
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		filtered := filterDeployVersionsForHostOS(catalog.Versions, hostOS)
		log.Printf("[api] POST /api/v1/servers/probe-host-versions: ip=%q os=%q versions=%d",
			ip, hostOS, len(filtered))
		writeJSON(w, http.StatusOK, probeHostVersionsResponse{
			OS:       hostOS,
			Versions: filtered,
		})
	}
}

type deployUpgradeVersionRequest struct {
	Name        string `json:"name"`
	IP          string `json:"ip"`
	User        string `json:"user"`
	Pass        string `json:"pass"`
	SSHPort     string `json:"ssh_port"`
	Token       string `json:"token"`
	VersionUUID string `json:"version_uuid"`
	LicenseType string `json:"license_type,omitempty"`
}

func deployLicenseUpgradeVersion(ctx context.Context, cfg config.Config, view store.ServerView, versionUUID string) (deployCreateServerResponse, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.DeployLicenseBaseURL), "/")
	if baseURL == "" {
		logDeployLicenseClientf("abort: DEPLOY_LICENSE_BASE_URL is empty (upgrade_version)")
		return deployCreateServerResponse{}, errors.New("deploy license base url is not configured")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		logDeployLicenseClientf("abort: invalid base URL (upgrade_version) err=%v", err)
		return deployCreateServerResponse{}, errors.New("deploy license base url is invalid")
	}
	reqPayload := deployUpgradeVersionRequest{
		Name:        strings.TrimSpace(view.Name),
		IP:          strings.TrimSpace(view.IP),
		User:        strings.TrimSpace(view.SSHUser),
		Pass:        strings.TrimSpace(view.SSHPassword),
		SSHPort:     strings.TrimSpace(view.SSHPort),
		Token:       strings.TrimSpace(view.Token),
		VersionUUID: strings.TrimSpace(versionUUID),
		LicenseType: deployLicenseServiceLicenseType(view.License),
	}
	body, err := json.Marshal(reqPayload)
	if err != nil {
		return deployCreateServerResponse{}, fmt.Errorf("encode upgrade_version request: %w", err)
	}
	timeout := cfg.DeployLicenseTimeoutSeconds
	if timeout <= 0 {
		timeout = 900
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	target := baseURL + "/upgrade_version"
	logDeployLicenseClientf("POST %s timeout=%ds serverID payload name=%q ip=%q version_uuid_len=%d",
		target, timeout, reqPayload.Name, reqPayload.IP, len(reqPayload.VersionUUID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return deployCreateServerResponse{}, fmt.Errorf("build upgrade_version request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		logDeployLicenseClientf("upgrade_version HTTP error: %v", err)
		return deployCreateServerResponse{}, fmt.Errorf("upgrade_version request failed: %w", err)
	}
	defer resp.Body.Close()
	limitedBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return deployCreateServerResponse{}, fmt.Errorf("read upgrade_version response: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return deployCreateServerResponse{}, fmt.Errorf("upgrade_version failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(limitedBody)))
	}
	var decoded deployCreateServerResponse
	if err := json.Unmarshal(limitedBody, &decoded); err != nil {
		return deployCreateServerResponse{}, fmt.Errorf("decode upgrade_version response: %w", err)
	}
	normalizeDeployLicenseCreateResponse(&decoded)
	return decoded, nil
}

type deployUpgradeLicenseRequest struct {
	Name        string `json:"name"`
	IP          string `json:"ip"`
	User        string `json:"user"`
	Pass        string `json:"pass"`
	SSHPort     string `json:"ssh_port"`
	Token       string `json:"token"`
	LicenseType string `json:"license_type"`
}

func deployLicenseUpgradeLicense(ctx context.Context, cfg config.Config, view store.ServerView, licenseType string) (deployCreateServerResponse, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.DeployLicenseBaseURL), "/")
	if baseURL == "" {
		logDeployLicenseClientf("abort: DEPLOY_LICENSE_BASE_URL is empty (upgrade_license)")
		return deployCreateServerResponse{}, errors.New("deploy license base url is not configured")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		logDeployLicenseClientf("abort: invalid base URL (upgrade_license) err=%v", err)
		return deployCreateServerResponse{}, errors.New("deploy license base url is invalid")
	}
	reqPayload := deployUpgradeLicenseRequest{
		Name:        strings.TrimSpace(view.Name),
		IP:          strings.TrimSpace(view.IP),
		User:        strings.TrimSpace(view.SSHUser),
		Pass:        strings.TrimSpace(view.SSHPassword),
		SSHPort:     strings.TrimSpace(view.SSHPort),
		Token:       strings.TrimSpace(view.Token),
		LicenseType: deployLicenseServiceLicenseType(licenseType),
	}
	body, err := json.Marshal(reqPayload)
	if err != nil {
		return deployCreateServerResponse{}, fmt.Errorf("encode upgrade_license request: %w", err)
	}
	timeout := cfg.DeployLicenseTimeoutSeconds
	if timeout <= 0 {
		timeout = 900
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	target := baseURL + "/upgrade_license"
	logDeployLicenseClientf("POST %s timeout=%ds server payload name=%q ip=%q license_type=%q",
		target, timeout, reqPayload.Name, reqPayload.IP, reqPayload.LicenseType)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return deployCreateServerResponse{}, fmt.Errorf("build upgrade_license request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		logDeployLicenseClientf("upgrade_license HTTP error: %v", err)
		return deployCreateServerResponse{}, fmt.Errorf("upgrade_license request failed: %w", err)
	}
	defer resp.Body.Close()
	limitedBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return deployCreateServerResponse{}, fmt.Errorf("read upgrade_license response: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return deployCreateServerResponse{}, fmt.Errorf("upgrade_license failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(limitedBody)))
	}
	var decoded deployCreateServerResponse
	if err := json.Unmarshal(limitedBody, &decoded); err != nil {
		return deployCreateServerResponse{}, fmt.Errorf("decode upgrade_license response: %w", err)
	}
	normalizeDeployLicenseCreateResponse(&decoded)
	return decoded, nil
}

type serverUpgradeRequestBody struct {
	VersionUUID string `json:"versionUuid"`
}

func handleServerRefreshRuntimeStatus(w http.ResponseWriter, r *http.Request, cfg config.Config, servers store.ServerStore, serverID int64) {
	view, err := servers.GetView(r.Context(), serverID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "server not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load server")
		return
	}
	deployServiceStatus, deployL4Status, deployL7Status := probeRemoteRuntimeStatuses(
		r.Context(),
		view.IP,
		view.SSHUser,
		view.SSHPassword,
		view.SSHPort,
	)
	tok := strings.TrimSpace(view.Token)
	if err := servers.UpdateDeploymentData(
		r.Context(),
		serverID,
		tok,
		"",
		"",
		"",
		"",
		nil,
		deployServiceStatus,
		deployL4Status,
		deployL7Status,
	); err != nil {
		log.Printf("[api] POST /servers/%d/refresh-runtime-status: UpdateDeploymentData failed: %v", serverID, err)
		writeError(w, http.StatusInternalServerError, "failed to persist runtime status")
		return
	}
	outView, err := servers.GetView(r.Context(), serverID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load server")
		return
	}
	log.Printf("[api] POST /servers/%d/refresh-runtime-status: ssh_target=%s@%s:%s angelos=%q l4=%q l7=%q",
		serverID,
		strings.TrimSpace(view.SSHUser),
		strings.TrimSpace(view.IP),
		strings.TrimSpace(view.SSHPort),
		outView.ServiceStatus,
		outView.L4Status,
		outView.L7Status,
	)
	writeJSON(w, http.StatusOK, outView)
}

func handleServerUpgrade(w http.ResponseWriter, r *http.Request, cfg config.Config, servers store.ServerStore, serverID int64) {
	var body serverUpgradeRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	versionUUID := strings.TrimSpace(body.VersionUUID)
	if versionUUID == "" {
		writeError(w, http.StatusBadRequest, "versionUuid is required")
		return
	}
	view, err := servers.GetView(r.Context(), serverID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "server not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load server")
		return
	}
	if strings.TrimSpace(view.Token) == "" {
		writeError(w, http.StatusBadRequest, "server has no deployment token")
		return
	}
	deployTimeout := cfg.DeployLicenseTimeoutSeconds
	if deployTimeout <= 0 {
		deployTimeout = 900
	}
	deployCtx, cancelDeploy := context.WithTimeout(r.Context(), time.Duration(deployTimeout)*time.Second)
	defer cancelDeploy()
	deployResp, err := deployLicenseUpgradeVersion(deployCtx, cfg, view, versionUUID)
	if err != nil {
		log.Printf("[api] POST /servers/%d/upgrade: deploy_license failed: %v", serverID, err)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	expireRaw := strings.TrimSpace(deployResp.DeployComplete.ExpireDate)
	if expireRaw == "" {
		expireRaw = strings.TrimSpace(deployResp.ExpireDate)
	}
	expiredAt, err := parseDeployExpireDate(expireRaw)
	if err != nil {
		log.Printf("[api] POST /servers/%d/upgrade: invalid expire_date raw=%q err=%v", serverID, expireRaw, err)
		writeError(w, http.StatusBadGateway, "deploy license returned invalid expire_date")
		return
	}
	deployServiceStatus, deployL4Status, deployL7Status := probeRemoteRuntimeStatuses(
		r.Context(),
		view.IP,
		view.SSHUser,
		view.SSHPassword,
		view.SSHPort,
	)
	deployVersion := strings.TrimSpace(deployResp.DeployComplete.Version)
	if deployVersion == "" {
		deployVersion = strings.TrimSpace(deployResp.Version)
	}
	deployOS := deployProductOS(deployResp)
	storedLicenseType := storeLicenseTypeFromDeployResponse(deployResp, view.License)
	tok := strings.TrimSpace(view.Token)
	if err := servers.UpdateDeploymentData(r.Context(), serverID, tok, "", storedLicenseType, deployVersion, deployOS, expiredAt, deployServiceStatus, deployL4Status, deployL7Status); err != nil {
		log.Printf("[api] POST /servers/%d/upgrade: UpdateDeploymentData failed: %v", serverID, err)
		writeError(w, http.StatusInternalServerError, "failed to persist upgrade result")
		return
	}
	outView, err := servers.GetView(r.Context(), serverID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load server")
		return
	}
	log.Printf("[api] POST /servers/%d/upgrade: success version=%q service_status=%q", serverID, outView.Version, outView.ServiceStatus)
	writeJSON(w, http.StatusOK, outView)
}

type serverUpgradeLicenseRequestBody struct {
	LicenseType string `json:"licenseType"`
}

func handleServerUpgradeLicense(w http.ResponseWriter, r *http.Request, cfg config.Config, servers store.ServerStore, serverID int64) {
	var body serverUpgradeLicenseRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	licenseType := strings.TrimSpace(body.LicenseType)
	if licenseType == "" {
		writeError(w, http.StatusBadRequest, "licenseType is required")
		return
	}
	view, err := servers.GetView(r.Context(), serverID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "server not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load server")
		return
	}
	if strings.TrimSpace(view.Token) == "" {
		writeError(w, http.StatusBadRequest, "server has no deployment token")
		return
	}
	deployTimeout := cfg.DeployLicenseTimeoutSeconds
	if deployTimeout <= 0 {
		deployTimeout = 900
	}
	deployCtx, cancelDeploy := context.WithTimeout(r.Context(), time.Duration(deployTimeout)*time.Second)
	defer cancelDeploy()
	deployResp, err := deployLicenseUpgradeLicense(deployCtx, cfg, view, licenseType)
	if err != nil {
		log.Printf("[api] POST /servers/%d/upgrade-license: deploy_license failed: %v", serverID, err)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	expireRaw := strings.TrimSpace(deployResp.DeployComplete.ExpireDate)
	if expireRaw == "" {
		expireRaw = strings.TrimSpace(deployResp.ExpireDate)
	}
	expiredAt, err := parseDeployExpireDate(expireRaw)
	if err != nil {
		log.Printf("[api] POST /servers/%d/upgrade-license: invalid expire_date raw=%q err=%v", serverID, expireRaw, err)
		writeError(w, http.StatusBadGateway, "deploy license returned invalid expire_date")
		return
	}
	deployServiceStatus, deployL4Status, deployL7Status := probeRemoteRuntimeStatuses(
		r.Context(),
		view.IP,
		view.SSHUser,
		view.SSHPassword,
		view.SSHPort,
	)
	deployVersion := strings.TrimSpace(deployResp.DeployComplete.Version)
	if deployVersion == "" {
		deployVersion = strings.TrimSpace(deployResp.Version)
	}
	storedLicenseType := storeLicenseTypeFromDeployResponse(deployResp, licenseType)
	tok := strings.TrimSpace(view.Token)
	if err := servers.UpdateDeploymentData(r.Context(), serverID, tok, "", storedLicenseType, deployVersion, "", expiredAt, deployServiceStatus, deployL4Status, deployL7Status); err != nil {
		log.Printf("[api] POST /servers/%d/upgrade-license: UpdateDeploymentData failed: %v", serverID, err)
		writeError(w, http.StatusInternalServerError, "failed to persist upgrade result")
		return
	}
	outView, err := servers.GetView(r.Context(), serverID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load server")
		return
	}
	log.Printf("[api] POST /servers/%d/upgrade-license: success license=%q version=%q service_status=%q", serverID, outView.License, outView.Version, outView.ServiceStatus)
	writeJSON(w, http.StatusOK, outView)
}

func parseDeployExpireDate(raw string) (*time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, trimmed)
		if err == nil {
			return &parsed, nil
		}
	}
	return nil, fmt.Errorf("unsupported expire_date format: %s", trimmed)
}

type serverUpdatePayload struct {
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Status      string `json:"status"`
	LicenseType string `json:"licenseType"`
	LicenseFile string `json:"licenseFile"`
	Version     string `json:"version"`
	SSHUser     string `json:"sshUser"`
	SSHPassword string `json:"sshPassword"`
	SSHPort     string `json:"sshPort"`
}

type wafWhitelistPayload struct {
	IPs         string `json:"ips"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Description string `json:"description"`
}

type wafWhitelistBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafBlacklistPayload struct {
	IPs         string `json:"ips"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Behavior    string `json:"behavior"`
	Description string `json:"description"`
}

type wafBlacklistBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafGeoPayload struct {
	Country   string `json:"country"`
	URL       string `json:"url"`
	Behavior  string `json:"behavior"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
}

type wafGeoBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafAntiCcPayload struct {
	URL       string `json:"url"`
	Method    string `json:"method"`
	Threshold int    `json:"threshold"`
	Window    int    `json:"window"`
	Action    string `json:"action"`
	Behavior  string `json:"behavior"`
	Status    string `json:"status"`
}

type wafAntiCcBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafAntiHeaderPayload struct {
	URL       string `json:"url"`
	Header    string `json:"header"`
	Value     string `json:"value"`
	BlockMode string `json:"blockMode"`
	Behavior  string `json:"behavior"`
	Status    string `json:"status"`
}

type wafAntiHeaderBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafIntervalPayload struct {
	URL          string `json:"url"`
	Time         int    `json:"time"`
	RequestCount int    `json:"requestCount"`
	Behavior     string `json:"behavior"`
	Status       string `json:"status"`
}

type wafIntervalBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafSecondPayload struct {
	URL          string `json:"url"`
	RequestCount int    `json:"requestCount"`
	Burst        int    `json:"burst"`
	Behavior     string `json:"behavior"`
	Status       string `json:"status"`
}

type wafSecondBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafResponsePayload struct {
	URL           string `json:"url"`
	ResponseCode  string `json:"responseCode"`
	Time          int    `json:"time"`
	ResponseCount int    `json:"responseCount"`
	Behavior      string `json:"behavior"`
	Status        string `json:"status"`
}

type wafResponseBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type wafUserAgentPayload struct {
	URL       string `json:"url"`
	UserAgent string `json:"userAgent"`
	Match     string `json:"match"`
	Behavior  string `json:"behavior"`
	Status    string `json:"status"`
}

type wafUserAgentBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type upstreamServerPayload struct {
	Address     string `json:"address"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type upstreamServerBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type listeningPortPayload struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type listeningPortBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type cacheRulePayload struct {
	RuleName         string `json:"ruleName"`
	RuleType         string `json:"ruleType"`
	CachingTime      int    `json:"cachingTime"`
	URL              string `json:"url"`
	FileTypes        string `json:"fileTypes"`
	Priority         int    `json:"priority"`
	CacheSlice       float64 `json:"cacheSlice"`
	WithoutParameter string `json:"withoutParameter"`
	CacheMode        string `json:"cacheMode"`
	Status           string `json:"status"`
}

type cacheRuleBatchPayload struct {
	IDs []int64 `json:"ids"`
}

type clearUrlCachePayload struct {
	MatchType    string `json:"matchType"`
	MatchContent string `json:"matchContent"`
}

type l7ClearUrlCachePayload struct {
	ServerID     int64  `json:"serverId"`
	MatchType    int    `json:"match_type"`
	MatchContent string `json:"match_content"`
}

type serverBlacklistPayload struct {
	ServerID    int64  `json:"serverId"`
	IPAddress   string `json:"ipAddress"`
	Geolocation string `json:"geolocation"`
	Reason      string `json:"reason"`
	URL         string `json:"url"`
	Server      string `json:"server"`
	TTL         string `json:"ttl"`
	TriggerRule string `json:"triggerRule"`
}

type l4BlacklistPayload struct {
	IPAddress string `json:"ipAddress"`
	Reason    string `json:"reason"`
}

type l4WhitelistPayload struct {
	IPAddress string `json:"ipAddress"`
	Reason    string `json:"reason"`
}

func serverBlacklistHandler(servers store.ServerStore, blacklist store.BlacklistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/servers/blacklist")
		if path == "" || path == "/" {
			switch r.Method {
			case http.MethodGet:
				var serverID int64
				rawServerID := strings.TrimSpace(r.URL.Query().Get("serverId"))
				if rawServerID != "" {
					parsed, ok := parsePositiveInt(rawServerID)
					if !ok {
						writeError(w, http.StatusBadRequest, "invalid serverId")
						return
					}
					serverID = parsed
				}
				list, err := blacklist.List(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load blacklist entries")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				var payload serverBlacklistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				if payload.ServerID == 0 {
					writeError(w, http.StatusBadRequest, "serverId is required")
					return
				}
				ipAddress := strings.TrimSpace(payload.IPAddress)
				if ipAddress == "" {
					writeError(w, http.StatusBadRequest, "ipAddress is required")
					return
				}
				geolocation := strings.TrimSpace(payload.Geolocation)
				if geolocation == "" {
					geolocation = "Manual"
				}
				reason := strings.TrimSpace(payload.Reason)
				if reason == "" {
					reason = "Manual block"
				}
				ttl := strings.TrimSpace(payload.TTL)
				triggerRule := strings.TrimSpace(payload.TriggerRule)
				serverName := strings.TrimSpace(payload.Server)
				url := strings.TrimSpace(payload.URL)

				created, err := blacklist.Create(r.Context(), payload.ServerID, store.BlacklistInput{
					IPAddress:   ipAddress,
					Geolocation: geolocation,
					Reason:      reason,
					URL:         url,
					Server:      serverName,
					TTL:         ttl,
					TriggerRule: triggerRule,
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create blacklist entry")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodDelete:
				var serverID int64
				rawServerID := strings.TrimSpace(r.URL.Query().Get("serverId"))
				if rawServerID != "" {
					parsed, ok := parsePositiveInt(rawServerID)
					if !ok {
						writeError(w, http.StatusBadRequest, "invalid serverId")
						return
					}
					serverID = parsed
				}
				if err := blacklist.DeleteAll(r.Context(), serverID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to flush blacklist entries")
					return
				}
				// After flushing the temporary blacklist for a server, notify api_parser.
				if serverID > 0 {
					if err := callL7UpdateTemporaryBlacklist(r.Context(), servers, serverID, blacklist); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync temporary blacklist")
						return
					}
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if !strings.HasPrefix(path, "/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		rawID := strings.TrimPrefix(path, "/")
		if rawID == "" || strings.Contains(rawID, "/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		entryID, ok := parsePositiveInt(rawID)
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if r.Method != http.MethodDelete {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		// Resolve serverID for this entry from query parameter if provided, or
		// from the stored payload as a fallback.
		var serverID int64
		if rawServerID := strings.TrimSpace(r.URL.Query().Get("serverId")); rawServerID != "" {
			parsed, ok := parsePositiveInt(rawServerID)
			if !ok {
				writeError(w, http.StatusBadRequest, "invalid serverId")
				return
			}
			serverID = parsed
		}
		if serverID == 0 {
			if payload, err := blacklist.GetPayload(r.Context(), entryID); err == nil {
				serverID = payload.ServerID
			}
		}
		if err := blacklist.Delete(r.Context(), entryID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to delete blacklist entry")
			return
		}
		// After deleting a single temporary blacklist entry, notify api_parser.
		if serverID > 0 {
			if err := callL7UpdateTemporaryBlacklist(r.Context(), servers, serverID, blacklist); err != nil {
				writeError(w, http.StatusBadGateway, "failed to sync temporary blacklist")
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func temporaryBlacklistAddedHandler(servers store.ServerStore, blacklist store.BlacklistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var payload store.TemporaryBlacklistPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if strings.TrimSpace(payload.IP) == "" {
			writeError(w, http.StatusBadRequest, "ip is required")
			return
		}
		token := strings.TrimSpace(payload.Token)
		if token == "" {
			writeError(w, http.StatusForbidden, "missing token")
			return
		}

		server, err := servers.GetByToken(r.Context(), token)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusForbidden, "invalid token")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to validate token")
			return
		}

		payload.ServerID = server.ID
		payload.Server = server.Name

		created, err := blacklist.CreateFromPayload(r.Context(), payload)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to store blacklist entry")
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

// l7WhitelistUpdatePayload is sent to api_parser's /api/l7_update_whitelist
// endpoint to keep the L7 (WAF) whitelist rules for a server in sync.
type l7WhitelistUpdatePayload struct {
	ServerID int64                    `json:"serverId"`
	ServerIP string                   `json:"serverIp"`
	Rules    []store.WafWhitelistRule `json:"rules"`
}

// callL7UpdateWhitelist loads all WAF whitelist rules for the given server and
// sends them to api_parser via the l7_update_whitelist API using POST.
func callL7UpdateWhitelist(ctx context.Context, servers store.ServerStore, serverID int64, wafWhitelist store.WafWhitelistStore) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	rules, err := wafWhitelist.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load waf whitelist rules: %w", err)
	}

	payload := l7WhitelistUpdatePayload{
		ServerID: server.ID,
		ServerIP: strings.TrimSpace(server.IP),
		Rules:    rules,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 whitelist payload: %w", err)
	}

	l7WhitelistUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_whitelist"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7WhitelistUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_whitelist request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_whitelist request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_whitelist returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

// l7BlacklistUpdatePayload is sent to api_parser's /api/l7_update_blacklist
// endpoint to keep the L7 (WAF) blacklist rules for a server in sync.
type l7BlacklistUpdatePayload struct {
	ServerID int64                    `json:"serverId"`
	ServerIP string                   `json:"serverIp"`
	Rules    []store.WafBlacklistRule `json:"rules"`
}

// callL7UpdateBlacklist loads all WAF blacklist rules for the given server and
// sends them to api_parser via the l7_update_blacklist API using POST.
func callL7UpdateBlacklist(ctx context.Context, servers store.ServerStore, serverID int64, wafBlacklist store.WafBlacklistStore) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	rules, err := wafBlacklist.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load waf blacklist rules: %w", err)
	}

	payload := l7BlacklistUpdatePayload{
		ServerID: server.ID,
		ServerIP: strings.TrimSpace(server.IP),
		Rules:    rules,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 blacklist payload: %w", err)
	}

	l7BlacklistUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_blacklist"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7BlacklistUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_blacklist request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_blacklist request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_blacklist returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

// l7GeoUpdatePayload is sent to api_parser's /api/l7_update_geo endpoint to
// keep the L7 (WAF) geolocation rules for a server in sync.
type l7GeoUpdatePayload struct {
	ServerID int64              `json:"serverId"`
	ServerIP string             `json:"serverIp"`
	Rules    []store.WafGeoRule `json:"rules"`
}

// callL7UpdateGeo loads all WAF GEO rules for the given server, filters to
// enabled ones only, normalizes behavior for WHITE operation, and sends them
// to api_parser via the l7_update_geo API using POST.
func callL7UpdateGeo(ctx context.Context, servers store.ServerStore, serverID int64, wafGeo store.WafGeoStore) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	allRules, err := wafGeo.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load waf geo rules: %w", err)
	}

	// Filter to enabled rules and enforce behavior=Allow for WHITE operation.
	normalized := make([]store.WafGeoRule, 0, len(allRules))
	for _, r := range allRules {
		if !strings.EqualFold(strings.TrimSpace(r.Status), "ENABLE") {
			continue
		}
		rule := r
		if strings.EqualFold(strings.TrimSpace(rule.Operation), "WHITE") {
			rule.Behavior = "Allow"
		}
		normalized = append(normalized, rule)
	}

	payload := l7GeoUpdatePayload{
		ServerID: server.ID,
		ServerIP: strings.TrimSpace(server.IP),
		Rules:    normalized,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 geo payload: %w", err)
	}

	l7GeoUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_geo"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7GeoUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_geo request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_geo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_geo returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

// l7AntiHeaderUpdatePayload is sent to api_parser's /API/L7/l7_update_antiheader
// endpoint to keep the L7 (WAF) anti-header rules for a server in sync.
type l7AntiHeaderUpdatePayload struct {
	ServerID int64                     `json:"serverId"`
	ServerIP string                    `json:"serverIp"`
	Rules    []store.WafAntiHeaderRule `json:"rules"`
}

// callL7UpdateAntiHeader loads all WAF anti-header rules for the given server,
// filters to enabled ones only, and sends them to api_parser via the
// l7_update_antiheader API using POST.
func callL7UpdateAntiHeader(ctx context.Context, servers store.ServerStore, serverID int64, wafAntiHeader store.WafAntiHeaderStore) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	allRules, err := wafAntiHeader.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load waf anti-header rules: %w", err)
	}

	// Only include rules whose status is ENABLE (case-insensitive).
	enabled := make([]store.WafAntiHeaderRule, 0, len(allRules))
	for _, r := range allRules {
		if !strings.EqualFold(strings.TrimSpace(r.Status), "ENABLE") {
			continue
		}
		enabled = append(enabled, r)
	}

	payload := l7AntiHeaderUpdatePayload{
		ServerID: server.ID,
		ServerIP: strings.TrimSpace(server.IP),
		Rules:    enabled,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 anti-header payload: %w", err)
	}

	l7AntiHeaderUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_antiheader"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7AntiHeaderUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_antiheader request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_antiheader request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_antiheader returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

// l7IntervalFreqLimitUpdatePayload is sent to api_parser's
// /API/L7/l7_update_intervalfreqlimit endpoint to keep the L7 (WAF)
// interval frequency limit rules for a server in sync.
type l7IntervalFreqLimitUpdatePayload struct {
	ServerID int64                          `json:"serverId"`
	ServerIP string                         `json:"serverIp"`
	Rules    []intervalFreqLimitRulePayload `json:"rules"`
}

// intervalFreqLimitRulePayload is the per-rule shape expected by api_parser.
type intervalFreqLimitRulePayload struct {
	ID           int64  `json:"id"`
	ServerID     int64  `json:"serverId"`
	URL          string `json:"url"`
	TimeSeconds  int    `json:"time"`
	RequestCount int    `json:"request_count"`
	Behavior     string `json:"behavior"`
	Status       string `json:"status"`
}

// callL7UpdateIntervalFreqLimit loads all WAF interval frequency limit rules
// for the given server, filters to enabled ones only, and sends them to
// api_parser via the l7_update_intervalfreqlimit API using POST.
func callL7UpdateIntervalFreqLimit(ctx context.Context, servers store.ServerStore, serverID int64, wafInterval store.WafIntervalStore) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	allRules, err := wafInterval.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load waf interval rules: %w", err)
	}

	enabled := make([]intervalFreqLimitRulePayload, 0, len(allRules))
	for _, r := range allRules {
		if !strings.EqualFold(strings.TrimSpace(r.Status), "ENABLE") {
			continue
		}
		enabled = append(enabled, intervalFreqLimitRulePayload{
			ID:           r.ID,
			ServerID:     r.ServerID,
			URL:          r.URL,
			TimeSeconds:  r.TimeSeconds,
			RequestCount: r.RequestCount,
			Behavior:     r.Behavior,
			Status:       r.Status,
		})
	}

	payload := l7IntervalFreqLimitUpdatePayload{
		ServerID: server.ID,
		ServerIP: strings.TrimSpace(server.IP),
		Rules:    enabled,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 intervalfreqlimit payload: %w", err)
	}

	l7IntervalFreqLimitUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_intervalfreqlimit"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7IntervalFreqLimitUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_intervalfreqlimit request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_intervalfreqlimit request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_intervalfreqlimit returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

// l7SecondFreqLimitUpdatePayload is sent to api_parser's
// /API/L7/l7_update_secondfreqlimit endpoint to keep the L7 (WAF)
// second frequency limit rules for a server in sync.
type l7SecondFreqLimitUpdatePayload struct {
	ServerID int64                        `json:"serverId"`
	ServerIP string                       `json:"serverIp"`
	Rules    []secondFreqLimitRulePayload `json:"rules"`
}

// secondFreqLimitRulePayload is the per-rule shape expected by api_parser.
type secondFreqLimitRulePayload struct {
	ID           int64  `json:"id"`
	ServerID     int64  `json:"serverId"`
	URL          string `json:"url"`
	RequestCount int    `json:"request_count"`
	Burst        int    `json:"burst"`
	Behavior     string `json:"behavior"`
	Status       string `json:"status"`
}

// callL7UpdateSecondFreqLimit loads all WAF second frequency limit rules
// for the given server, filters to enabled ones only, and sends them to
// api_parser via the l7_update_secondfreqlimit API using POST.
func callL7UpdateSecondFreqLimit(ctx context.Context, servers store.ServerStore, serverID int64, wafSecond store.WafSecondStore) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	allRules, err := wafSecond.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load waf second rules: %w", err)
	}

	enabled := make([]secondFreqLimitRulePayload, 0, len(allRules))
	for _, r := range allRules {
		if !strings.EqualFold(strings.TrimSpace(r.Status), "ENABLE") {
			continue
		}
		enabled = append(enabled, secondFreqLimitRulePayload{
			ID:           r.ID,
			ServerID:     r.ServerID,
			URL:          r.URL,
			RequestCount: r.RequestCount,
			Burst:        r.Burst,
			Behavior:     r.Behavior,
			Status:       r.Status,
		})
	}

	payload := l7SecondFreqLimitUpdatePayload{
		ServerID: server.ID,
		ServerIP: strings.TrimSpace(server.IP),
		Rules:    enabled,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 secondfreqlimit payload: %w", err)
	}

	l7SecondFreqLimitUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_secondfreqlimit"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7SecondFreqLimitUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_secondfreqlimit request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_secondfreqlimit request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_secondfreqlimit returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

// l7TemporaryBlacklistUpdatePayload is sent to api_parser's
// /API/L7/l7_update_temporaryblacklist endpoint to keep the temporary blacklist
// entries in sync for a server.
type l7TemporaryBlacklistUpdatePayload struct {
	ServerID           int64                             `json:"serverId"`
	TemporaryBlacklist []l7TemporaryBlacklistUpdateEntry `json:"temporaryblacklist"`
}

// l7TemporaryBlacklistUpdateEntry represents a single temporary blacklist item
// as expected by api_parser.
type l7TemporaryBlacklistUpdateEntry struct {
	IP          string `json:"ip"`
	URL         string `json:"url"`
	Country     string `json:"country"`
	City        string `json:"city"`
	BlockedAt   string `json:"blocked_at"`
	TTL         int64  `json:"ttl"`
	TriggerRule string `json:"trigger_rule"`
}

// callL7UpdateTemporaryBlacklist loads all temporary blacklist payloads for the
// given server and sends them to api_parser via the l7_update_temporaryblacklist
// API using POST.
func callL7UpdateTemporaryBlacklist(ctx context.Context, servers store.ServerStore, serverID int64, blacklist store.BlacklistStore) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	payloads, err := blacklist.ListPayloadsByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load temporary blacklist payloads: %w", err)
	}

	items := make([]l7TemporaryBlacklistUpdateEntry, 0, len(payloads))
	for _, p := range payloads {
		items = append(items, l7TemporaryBlacklistUpdateEntry{
			IP:          strings.TrimSpace(p.IP),
			URL:         strings.TrimSpace(p.URL),
			Country:     strings.TrimSpace(p.Country),
			City:        strings.TrimSpace(p.City),
			BlockedAt:   strings.TrimSpace(p.BlockedAt),
			TTL:         p.TTL,
			TriggerRule: strings.TrimSpace(p.TriggerRule),
		})
	}

	body, err := json.Marshal(l7TemporaryBlacklistUpdatePayload{
		ServerID:           serverID,
		TemporaryBlacklist: items,
	})
	if err != nil {
		return fmt.Errorf("encode l7 temporary blacklist payload: %w", err)
	}

	l7TemporaryBlacklistUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_temporaryblacklist"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7TemporaryBlacklistUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_temporaryblacklist request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_temporaryblacklist request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_temporaryblacklist returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

// l7ResponseFreqUpdatePayload is sent to api_parser's
// /API/L7/l7_update_responsefreq endpoint to keep the L7 (WAF)
// response frequency rules for a server in sync.
type l7ResponseFreqUpdatePayload struct {
	ServerID int64                     `json:"serverId"`
	ServerIP string                    `json:"serverIp"`
	Rules    []responseFreqRulePayload `json:"rules"`
}

// responseFreqRulePayload is the per-rule shape expected by api_parser.
type responseFreqRulePayload struct {
	ID            int64  `json:"id"`
	ServerID      int64  `json:"serverId"`
	URL           string `json:"url"`
	ResponseCode  string `json:"response_code"`
	TimeSeconds   int    `json:"time"`
	ResponseCount int    `json:"response_count"`
	Behavior      string `json:"behavior"`
	Status        string `json:"status"`
}

// callL7UpdateResponseFreq loads all WAF response frequency rules for the
// given server, filters to enabled ones only, and sends them to api_parser
// via the l7_update_responsefreq API using POST.
func callL7UpdateResponseFreq(ctx context.Context, servers store.ServerStore, serverID int64, wafResponse store.WafResponseStore) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	allRules, err := wafResponse.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load waf response freq rules: %w", err)
	}

	enabled := make([]responseFreqRulePayload, 0, len(allRules))
	for _, r := range allRules {
		if !strings.EqualFold(strings.TrimSpace(r.Status), "ENABLE") {
			continue
		}
		enabled = append(enabled, responseFreqRulePayload{
			ID:            r.ID,
			ServerID:      r.ServerID,
			URL:           r.URL,
			ResponseCode:  r.ResponseCode,
			TimeSeconds:   r.TimeSeconds,
			ResponseCount: r.ResponseCount,
			Behavior:      r.Behavior,
			Status:        r.Status,
		})
	}

	payload := l7ResponseFreqUpdatePayload{
		ServerID: server.ID,
		ServerIP: strings.TrimSpace(server.IP),
		Rules:    enabled,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 responsefreq payload: %w", err)
	}

	l7ResponseFreqUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_responsefreq"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7ResponseFreqUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_responsefreq request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_responsefreq request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_responsefreq returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

// l7UserAgentUpdatePayload is sent to api_parser's
// /API/L7/l7_update_useragent endpoint to keep the L7 (WAF) user agent rules
// for a server in sync.
type l7UserAgentUpdatePayload struct {
	ServerID int64                  `json:"serverId"`
	ServerIP string                 `json:"serverIp"`
	Rules    []userAgentRulePayload `json:"rules"`
}

// userAgentRulePayload is the per-rule shape expected by api_parser.
type userAgentRulePayload struct {
	ID        int64  `json:"id"`
	ServerID  int64  `json:"serverId"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent"`
	Match     string `json:"match"`
	Behavior  string `json:"behavior"`
	Status    string `json:"status"`
}

// callL7UpdateUserAgent loads all WAF user agent rules for the given server,
// filters to enabled ones only, and sends them to api_parser via the
// l7_update_useragent API using POST.
func callL7UpdateUserAgent(ctx context.Context, servers store.ServerStore, serverID int64, wafUserAgent store.WafUserAgentStore) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	allRules, err := wafUserAgent.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load waf user agent rules: %w", err)
	}

	enabled := make([]userAgentRulePayload, 0, len(allRules))
	for _, r := range allRules {
		if !strings.EqualFold(strings.TrimSpace(r.Status), "ENABLE") {
			continue
		}
		enabled = append(enabled, userAgentRulePayload{
			ID:        r.ID,
			ServerID:  r.ServerID,
			URL:       r.URL,
			UserAgent: r.UserAgent,
			Match:     r.Match,
			Behavior:  r.Behavior,
			Status:    r.Status,
		})
	}

	payload := l7UserAgentUpdatePayload{
		ServerID: server.ID,
		ServerIP: strings.TrimSpace(server.IP),
		Rules:    enabled,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 useragent payload: %w", err)
	}

	l7UserAgentUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_useragent"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7UserAgentUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_useragent request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_useragent request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_useragent returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

// l7UpstreamServersUpdatePayload is sent to api_parser's
// /API/L7/l7_update_upstreamservers endpoint when upstream servers change.
type l7UpstreamServersUpdatePayload struct {
	ServerID  int64                     `json:"serverId"`
	Upstreams []upstreamServerPayloadL7 `json:"upstreams"`
}

// upstreamServerPayloadL7 is the per-upstream shape expected by api_parser.
type upstreamServerPayloadL7 struct {
	ID          int64  `json:"id"`
	ServerID    int64  `json:"serverId"`
	IpPort      string `json:"ip_port"`
	Description string `json:"description"`
}

func upstreamServersToL7Payload(list []store.UpstreamServer) []upstreamServerPayloadL7 {
	upstreams := make([]upstreamServerPayloadL7, 0, len(list))
	for _, u := range list {
		upstreams = append(upstreams, upstreamServerPayloadL7{
			ID:          u.ID,
			ServerID:    u.ServerID,
			IpPort:      strings.TrimSpace(u.Address),
			Description: strings.TrimSpace(u.Description),
		})
	}
	return upstreams
}

func postL7UpstreamServers(ctx context.Context, servers store.ServerStore, serverID int64, upstreams []upstreamServerPayloadL7) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	payload := l7UpstreamServersUpdatePayload{
		ServerID:  serverID,
		Upstreams: upstreams,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 upstreamservers payload: %w", err)
	}

	l7UpstreamServersUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_upstreamservers"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7UpstreamServersUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_upstreamservers request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_upstreamservers request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_upstreamservers returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

// callL7UpdateUpstreamServers loads all upstream servers for the given server
// and sends them to api_parser via the l7_update_upstreamservers API using POST.
func callL7UpdateUpstreamServers(ctx context.Context, servers store.ServerStore, serverID int64, upstreamServers store.UpstreamServerStore) error {
	list, err := upstreamServers.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load upstream servers: %w", err)
	}
	return postL7UpstreamServers(ctx, servers, serverID, upstreamServersToL7Payload(list))
}

// l7ListeningPortsUpdatePayload is sent to api_parser's
// /API/L7/l7_update_listeningports endpoint when listening ports change.
type l7ListeningPortsUpdatePayload struct {
	ServerID       int64                     `json:"serverId"`
	ListeningPorts []listeningPortPayloadL7 `json:"listeningports"`
}

// listeningPortPayloadL7 is the per-port shape expected by api_parser.
type listeningPortPayloadL7 struct {
	ID          int64  `json:"id"`
	ServerID    int64  `json:"serverId"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

func listeningPortsToL7Payload(list []store.ListeningPort) []listeningPortPayloadL7 {
	ports := make([]listeningPortPayloadL7, 0, len(list))
	for _, p := range list {
		ports = append(ports, listeningPortPayloadL7{
			ID:          p.ID,
			ServerID:    p.ServerID,
			Port:        p.Port,
			Protocol:    strings.TrimSpace(p.Protocol),
			Description: strings.TrimSpace(p.Description),
			Status:      strings.TrimSpace(p.Status),
		})
	}
	return ports
}

func postL7ListeningPorts(ctx context.Context, servers store.ServerStore, serverID int64, ports []listeningPortPayloadL7) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	payload := l7ListeningPortsUpdatePayload{
		ServerID:       serverID,
		ListeningPorts: ports,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 listeningports payload: %w", err)
	}

	l7ListeningPortsUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_listeningports"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7ListeningPortsUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_listeningports request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_listeningports request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_listeningports returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

// callL7UpdateListeningPorts loads all listening ports for the given server
// and sends them to api_parser via the l7_update_listeningports API using POST.
func callL7UpdateListeningPorts(ctx context.Context, servers store.ServerStore, serverID int64, listeningPorts store.ListeningPortStore) error {
	list, err := listeningPorts.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load listening ports: %w", err)
	}
	return postL7ListeningPorts(ctx, servers, serverID, listeningPortsToL7Payload(list))
}

// l7CacheRulesUpdatePayload is sent to api_parser's
// /API/L7/l7_update_cacherules endpoint when cache rules change.
type l7CacheRulesUpdatePayload struct {
	ServerID   int64                `json:"serverId"`
	CacheRules []cacheRulePayloadL7 `json:"cacherules"`
}

// cacheRulePayloadL7 is the per-rule shape expected by api_parser.
type cacheRulePayloadL7 struct {
	ID               int64  `json:"id"`
	ServerID         int64  `json:"serverId"`
	RuleName         string `json:"rule_name"`
	RuleType         string `json:"rule_type"`
	CachingTime      int    `json:"caching_time"`
	URL              string `json:"url"`
	FileTypes        string `json:"file_types"`
	Priority         int    `json:"priority"`
	CacheSlice       float64 `json:"cache_slice"`
	WithoutParameter string `json:"without_parameter"`
	CacheMode        string `json:"cache_mode"`
	Status           string `json:"status"`
}

func cacheRulesToL7Payload(list []store.CacheRule) []cacheRulePayloadL7 {
	rules := make([]cacheRulePayloadL7, 0, len(list))
	for _, rule := range list {
		rules = append(rules, cacheRulePayloadL7{
			ID:               rule.ID,
			ServerID:         rule.ServerID,
			RuleName:         strings.TrimSpace(rule.RuleName),
			RuleType:         strings.TrimSpace(rule.RuleType),
			CachingTime:      rule.CachingTime,
			URL:              strings.TrimSpace(rule.URL),
			FileTypes:        strings.TrimSpace(rule.FileTypes),
			Priority:         rule.Priority,
			CacheSlice:       rule.CacheSlice,
			WithoutParameter: strings.TrimSpace(rule.WithoutParameter),
			CacheMode:        strings.TrimSpace(rule.CacheMode),
			Status:           strings.TrimSpace(rule.Status),
		})
	}
	return rules
}

func postL7CacheRules(ctx context.Context, servers store.ServerStore, serverID int64, rules []cacheRulePayloadL7) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	payload := l7CacheRulesUpdatePayload{
		ServerID:   serverID,
		CacheRules: rules,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 cacherules payload: %w", err)
	}

	l7CacheRulesUpdateURL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_update_cacherules"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7CacheRulesUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_update_cacherules request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_update_cacherules request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_update_cacherules returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

func callL7UpdateCacheRules(ctx context.Context, servers store.ServerStore, serverID int64, cacheRules store.CacheRuleStore) error {
	list, err := cacheRules.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load cache rules: %w", err)
	}
	return postL7CacheRules(ctx, servers, serverID, cacheRulesToL7Payload(list))
}

type l7CacheActionPayload struct {
	ServerID int64 `json:"serverId"`
}

func postL7CacheClear(ctx context.Context, servers store.ServerStore, serverID int64, endpoint string) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}
	if strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("invalid l7 cache endpoint")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	payload := l7CacheActionPayload{ServerID: serverID}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7 %s payload: %w", endpoint, err)
	}

	l7URL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/" + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build %s request: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s returned status %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

func normalizeClearUrlCacheMatchType(matchType string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(matchType)) {
	case "prefix", "prefix_match", "prefix match":
		return "prefix_match", ""
	case "exact", "exact_match", "exact match":
		return "exact_match", ""
	case "advanced", "advanced_match", "advanced match":
		return "advanced_match", ""
	default:
		return "", "match type must be prefix, exact, or advanced"
	}
}

func validateClearUrlCacheContent(matchType, content string) string {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return "match content is required"
	}

	lower := strings.ToLower(trimmed)
	switch matchType {
	case "prefix_match":
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			return "match content must start with http:// or https://"
		}
		if !strings.HasSuffix(trimmed, "/") {
			return "prefix match content must end with /"
		}
	case "exact_match":
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			return "match content must start with http:// or https://"
		}
	case "advanced_match":
		// Any non-empty string is accepted for advanced match.
	}

	return ""
}

// clearUrlCacheMatchTypeToL7 maps normalized match types to the integer values
// expected by api_parser's l7_clear_url_cache endpoint (CDNRAY: 1=prefix, 2=exact, 3=advanced).
func clearUrlCacheMatchTypeToL7(matchType string) (int, string) {
	switch matchType {
	case "prefix_match":
		return 1, ""
	case "exact_match":
		return 2, ""
	case "advanced_match":
		return 3, ""
	default:
		return 0, "match type must be prefix, exact, or advanced"
	}
}

func postL7ClearUrlCache(ctx context.Context, servers store.ServerStore, serverID int64, matchType, matchContent string) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}

	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}

	l7MatchType, validationErr := clearUrlCacheMatchTypeToL7(matchType)
	if validationErr != "" {
		return fmt.Errorf(validationErr)
	}

	payload := l7ClearUrlCachePayload{
		ServerID:     serverID,
		MatchType:    l7MatchType,
		MatchContent: matchContent,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode l7_clear_url_cache payload: %w", err)
	}

	l7URL := "http://" + strings.TrimSpace(server.IP) + ":5000/API/L7/l7_clear_url_cache"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7_clear_url_cache request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7_clear_url_cache request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("l7_clear_url_cache returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}

	return nil
}

func cacheRulePayloadToInput(payload cacheRulePayload) (store.CacheRuleInput, string) {
	ruleName := store.NormalizeCacheRuleName(payload.RuleName)
	if ruleName == "" {
		return store.CacheRuleInput{}, "rule name is required"
	}

	ruleType := strings.ToLower(strings.TrimSpace(payload.RuleType))
	if ruleType == "" {
		ruleType = "file"
	}
	if ruleType != "file" && ruleType != "url" {
		return store.CacheRuleInput{}, "rule type must be file or url"
	}

	cachingTime := payload.CachingTime
	if cachingTime < 0 {
		cachingTime = 0
	}

	url := strings.TrimSpace(payload.URL)
	fileTypes := strings.TrimSpace(payload.FileTypes)
	if ruleType == "file" && fileTypes == "" {
		return store.CacheRuleInput{}, "file types are required for file rules"
	}
	if ruleType == "url" && url == "" {
		return store.CacheRuleInput{}, "url is required for url rules"
	}

	priority := payload.Priority
	if priority < 0 {
		priority = 0
	}

	cacheSlice := payload.CacheSlice
	if cacheSlice < 0 {
		cacheSlice = 0
	}

	withoutParameter := strings.ToLower(strings.TrimSpace(payload.WithoutParameter))
	if withoutParameter == "" {
		withoutParameter = "yes"
	}
	if withoutParameter != "yes" && withoutParameter != "no" {
		return store.CacheRuleInput{}, "without parameter must be yes or no"
	}

	cacheMode := strings.ToLower(strings.TrimSpace(payload.CacheMode))
	if cacheMode == "" {
		cacheMode = "origin"
	}
	if cacheMode != "origin" && cacheMode != "force" {
		return store.CacheRuleInput{}, "cache mode must be origin or force"
	}

	status := strings.ToUpper(strings.TrimSpace(payload.Status))
	if status == "" {
		status = "ENABLE"
	}
	if status != "ENABLE" && status != "DISABLE" {
		return store.CacheRuleInput{}, "status must be ENABLE or DISABLE"
	}

	return store.CacheRuleInput{
		RuleName:         ruleName,
		RuleType:         ruleType,
		CachingTime:      cachingTime,
		URL:              url,
		FileTypes:        fileTypes,
		Priority:         priority,
		CacheSlice:       cacheSlice,
		WithoutParameter: withoutParameter,
		CacheMode:        cacheMode,
		Status:           status,
	}, ""
}

func serverDetailHandler(
	cfg config.Config,
	agentClient *AgentClient,
	servers store.ServerStore,
	l4 store.L4Store,
	l4Whitelist store.L4WhitelistStore,
	l4Blacklist store.L4BlacklistStore,
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
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/host-metrics") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/host-metrics")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if r.Method != http.MethodGet {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			handleServerHostMetrics(w, r, servers, serverID)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/host-power") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/host-power")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			handleServerHostPower(w, r, servers, serverID)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/service-control") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/service-control")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			handleServerServiceControl(w, r, cfg, servers, serverID)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/refresh-runtime-status") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/refresh-runtime-status")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			handleServerRefreshRuntimeStatus(w, r, cfg, servers, serverID)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/upgrade-license") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/upgrade-license")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			handleServerUpgradeLicense(w, r, cfg, servers, serverID)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/upgrade") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/upgrade")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			handleServerUpgrade(w, r, cfg, servers, serverID)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/access-log/stream") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/access-log/stream")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			streamAccessLog(w, r, servers, serverID)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/users") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/users")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if r.Method != http.MethodPut {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			var payload serverUsersPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			if err := servers.UpdateServerUsers(r.Context(), serverID, payload.UserIDs); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to update server users")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/l4/options") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/l4/options")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if r.Method != http.MethodGet {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			if agentClient == nil {
				writeError(w, http.StatusInternalServerError, "agent client not configured")
				return
			}
			server, err := servers.GetView(r.Context(), serverID)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "server not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to load server data")
				return
			}
			options, err := agentClient.FetchL4Options(r.Context(), server.IP, server.Token)
			if err != nil {
				var agentErr AgentResponseError
				if errors.As(err, &agentErr) {
					writeError(w, http.StatusBadGateway, agentErr.Error())
					return
				}
				writeError(w, http.StatusBadGateway, "failed to load l4 options from server agent")
				return
			}
			writeJSON(w, http.StatusOK, options)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/l4") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/l4")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			switch r.Method {
			case http.MethodGet:
				config, err := l4.GetByServerID(r.Context(), serverID)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "l4 config not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to load l4 config")
					return
				}
				writeJSON(w, http.StatusOK, config)
			case http.MethodPut:
				var payload store.L4Config
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				if agentClient == nil {
					writeError(w, http.StatusInternalServerError, "agent client not configured")
					return
				}
				server, err := servers.GetView(r.Context(), serverID)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to load server data")
					return
				}
				if err := agentClient.PushL4(r.Context(), server.IP, server.Token, payload); err != nil {
					var agentErr AgentResponseError
					if errors.As(err, &agentErr) {
						writeError(w, http.StatusBadGateway, agentErr.Error())
						return
					}
					writeError(w, http.StatusBadGateway, "failed to apply l4 config to server agent")
					return
				}
				if err := l4.UpdateByServerID(r.Context(), serverID, payload); err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "l4 config not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update l4 config")
					return
				}
				updated, err := l4.GetByServerID(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load l4 config")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.HasSuffix(r.URL.Path, "/l4/blacklist/clear") && r.Method == http.MethodPost {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/l4/blacklist/clear")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if agentClient == nil {
				writeError(w, http.StatusInternalServerError, "agent client not configured")
				return
			}
			server, err := servers.GetView(r.Context(), serverID)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "server not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to load server data")
				return
			}
			if err := agentClient.ClearL4Blacklist(r.Context(), server.IP, server.Token); err != nil {
				var agentErr AgentResponseError
				if errors.As(err, &agentErr) {
					writeError(w, http.StatusBadGateway, agentErr.Error())
					return
				}
				writeError(w, http.StatusBadGateway, "failed to clear l4 blacklist on server agent")
				return
			}
			if err := l4Blacklist.DeleteAll(r.Context(), serverID); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to flush l4 blacklist entries")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if strings.Contains(r.URL.Path, "/l4/blacklist/remove/") && r.Method == http.MethodPost {
			trimmed := strings.TrimPrefix(r.URL.Path, "/servers/")
			parts := strings.Split(trimmed, "/")
			if len(parts) != 5 || parts[1] != "l4" || parts[2] != "blacklist" || parts[3] != "remove" {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			serverID, ok := parsePositiveInt(parts[0])
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			entryID, ok := parsePositiveInt(parts[4])
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if agentClient == nil {
				writeError(w, http.StatusInternalServerError, "agent client not configured")
				return
			}
			entries, err := l4Blacklist.ListByServer(r.Context(), serverID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load l4 blacklist entries")
				return
			}
			var ipToRemove string
			for _, e := range entries {
				if e.ID == entryID {
					ipToRemove = strings.TrimSpace(e.IPAddress)
					break
				}
			}
			if ipToRemove == "" {
				writeError(w, http.StatusNotFound, "l4 blacklist entry not found")
				return
			}
			server, err := servers.GetView(r.Context(), serverID)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "server not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to load server data")
				return
			}
			if err := agentClient.RemoveL4BlacklistIP(r.Context(), server.IP, server.Token, ipToRemove); err != nil {
				var agentErr AgentResponseError
				if errors.As(err, &agentErr) {
					writeError(w, http.StatusBadGateway, agentErr.Error())
					return
				}
				writeError(w, http.StatusBadGateway, "failed to remove l4 blacklist ip from server agent")
				return
			}
			if err := l4Blacklist.Delete(r.Context(), serverID, entryID); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to delete l4 blacklist entry")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if strings.Contains(r.URL.Path, "/l4/blacklist") {
			serverID, entryID, ok := parseL4BlacklistPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if entryID != 0 {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := l4Blacklist.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load l4 blacklist entries")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if entryID != 0 {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if agentClient == nil {
					writeError(w, http.StatusInternalServerError, "agent client not configured")
					return
				}
				var payload l4BlacklistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				ipAddress := strings.TrimSpace(payload.IPAddress)
				if ipAddress == "" {
					writeError(w, http.StatusBadRequest, "ipAddress is required")
					return
				}
				reason := strings.TrimSpace(payload.Reason)
				if reason == "" {
					reason = "Manual block"
				}
				server, err := servers.GetView(r.Context(), serverID)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to load server data")
					return
				}
				if err := agentClient.AddL4BlacklistIP(r.Context(), server.IP, server.Token, ipAddress); err != nil {
					var agentErr AgentResponseError
					if errors.As(err, &agentErr) {
						writeError(w, http.StatusBadGateway, agentErr.Error())
						return
					}
					writeError(w, http.StatusBadGateway, "failed to apply l4 blacklist ip to server agent")
					return
				}
				created, err := l4Blacklist.Create(r.Context(), serverID, store.L4BlacklistInput{
					IPAddress: ipAddress,
					Reason:    reason,
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create l4 blacklist entry")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.HasSuffix(r.URL.Path, "/l4/whitelist/clear") && r.Method == http.MethodPost {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/l4/whitelist/clear")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if agentClient == nil {
				writeError(w, http.StatusInternalServerError, "agent client not configured")
				return
			}
			server, err := servers.GetView(r.Context(), serverID)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "server not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to load server data")
				return
			}
			if err := agentClient.ClearL4Whitelist(r.Context(), server.IP, server.Token); err != nil {
				var agentErr AgentResponseError
				if errors.As(err, &agentErr) {
					writeError(w, http.StatusBadGateway, agentErr.Error())
					return
				}
				writeError(w, http.StatusBadGateway, "failed to clear l4 whitelist on server agent")
				return
			}
			if err := l4Whitelist.DeleteAll(r.Context(), serverID); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to clear l4 whitelist entries")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if strings.Contains(r.URL.Path, "/l4/whitelist/remove/") && r.Method == http.MethodPost {
			trimmed := strings.TrimPrefix(r.URL.Path, "/servers/")
			parts := strings.Split(trimmed, "/")
			if len(parts) != 5 || parts[1] != "l4" || parts[2] != "whitelist" || parts[3] != "remove" {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			serverID, ok := parsePositiveInt(parts[0])
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			entryID, ok := parsePositiveInt(parts[4])
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if agentClient == nil {
				writeError(w, http.StatusInternalServerError, "agent client not configured")
				return
			}
			entries, err := l4Whitelist.ListByServer(r.Context(), serverID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load l4 whitelist entries")
				return
			}
			var ipToRemove string
			for _, e := range entries {
				if e.ID == entryID {
					ipToRemove = strings.TrimSpace(e.IPAddress)
					break
				}
			}
			if ipToRemove == "" {
				writeError(w, http.StatusNotFound, "l4 whitelist entry not found")
				return
			}
			server, err := servers.GetView(r.Context(), serverID)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "server not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to load server data")
				return
			}
			if err := agentClient.RemoveL4WhitelistIP(r.Context(), server.IP, server.Token, ipToRemove); err != nil {
				var agentErr AgentResponseError
				if errors.As(err, &agentErr) {
					writeError(w, http.StatusBadGateway, agentErr.Error())
					return
				}
				writeError(w, http.StatusBadGateway, "failed to remove l4 whitelist ip from server agent")
				return
			}
			if err := l4Whitelist.Delete(r.Context(), serverID, entryID); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to delete l4 whitelist entry")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if strings.Contains(r.URL.Path, "/l4/whitelist") {
			serverID, entryID, ok := parseL4WhitelistPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if entryID != 0 {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := l4Whitelist.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load l4 whitelist entries")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if entryID != 0 {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if agentClient == nil {
					writeError(w, http.StatusInternalServerError, "agent client not configured")
					return
				}
				var payload l4WhitelistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				ipAddress := strings.TrimSpace(payload.IPAddress)
				if ipAddress == "" {
					writeError(w, http.StatusBadRequest, "ipAddress is required")
					return
				}
				reason := strings.TrimSpace(payload.Reason)
				if reason == "" {
					reason = "Manual whitelist"
				}
				server, err := servers.GetView(r.Context(), serverID)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to load server data")
					return
				}
				if err := agentClient.AddL4WhitelistIP(r.Context(), server.IP, server.Token, ipAddress); err != nil {
					var agentErr AgentResponseError
					if errors.As(err, &agentErr) {
						writeError(w, http.StatusBadGateway, agentErr.Error())
						return
					}
					writeError(w, http.StatusBadGateway, "failed to apply l4 whitelist ip to server agent")
					return
				}
				created, err := l4Whitelist.Create(r.Context(), serverID, store.L4WhitelistInput{
					IPAddress: ipAddress,
					Reason:    reason,
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create l4 whitelist entry")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodDelete:
				if entryID == 0 {
					if agentClient == nil {
						writeError(w, http.StatusInternalServerError, "agent client not configured")
						return
					}
					server, err := servers.GetView(r.Context(), serverID)
					if err != nil {
						if store.IsNotFound(err) {
							writeError(w, http.StatusNotFound, "server not found")
							return
						}
						writeError(w, http.StatusInternalServerError, "failed to load server data")
						return
					}
					if err := agentClient.ClearL4Whitelist(r.Context(), server.IP, server.Token); err != nil {
						var agentErr AgentResponseError
						if errors.As(err, &agentErr) {
							writeError(w, http.StatusBadGateway, agentErr.Error())
							return
						}
						writeError(w, http.StatusBadGateway, "failed to clear l4 whitelist on server agent")
						return
					}
					if err := l4Whitelist.DeleteAll(r.Context(), serverID); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to clear l4 whitelist entries")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if agentClient == nil {
					writeError(w, http.StatusInternalServerError, "agent client not configured")
					return
				}
				entries, err := l4Whitelist.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load l4 whitelist entries")
					return
				}
				var ipToRemove string
				for _, e := range entries {
					if e.ID == entryID {
						ipToRemove = strings.TrimSpace(e.IPAddress)
						break
					}
				}
				if ipToRemove == "" {
					writeError(w, http.StatusNotFound, "l4 whitelist entry not found")
					return
				}
				server, err := servers.GetView(r.Context(), serverID)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to load server data")
					return
				}
				if err := agentClient.RemoveL4WhitelistIP(r.Context(), server.IP, server.Token, ipToRemove); err != nil {
					var agentErr AgentResponseError
					if errors.As(err, &agentErr) {
						writeError(w, http.StatusBadGateway, agentErr.Error())
						return
					}
					writeError(w, http.StatusBadGateway, "failed to remove l4 whitelist ip from server agent")
					return
				}
				if err := l4Whitelist.Delete(r.Context(), serverID, entryID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete l4 whitelist entry")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/whitelist") {
			serverID, ruleID, isBatch, ok := parseWafWhitelistPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafWhitelist.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load whitelist rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafWhitelistBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafWhitelist.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					if err := callL7UpdateWhitelist(r.Context(), servers, serverID, wafWhitelist); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf whitelist rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafWhitelistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafWhitelist.Create(r.Context(), serverID, store.WafWhitelistInput{
					IPs:         strings.TrimSpace(payload.IPs),
					URL:         strings.TrimSpace(payload.URL),
					Method:      strings.TrimSpace(payload.Method),
					Description: strings.TrimSpace(payload.Description),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create whitelist rule")
					return
				}
				if err := callL7UpdateWhitelist(r.Context(), servers, serverID, wafWhitelist); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf whitelist rules")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafWhitelistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafWhitelist.Update(r.Context(), serverID, ruleID, store.WafWhitelistInput{
					IPs:         strings.TrimSpace(payload.IPs),
					URL:         strings.TrimSpace(payload.URL),
					Method:      strings.TrimSpace(payload.Method),
					Description: strings.TrimSpace(payload.Description),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "whitelist rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update whitelist rule")
					return
				}
				if err := callL7UpdateWhitelist(r.Context(), servers, serverID, wafWhitelist); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf whitelist rules")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafWhitelist.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete whitelist rule")
					return
				}
				if err := callL7UpdateWhitelist(r.Context(), servers, serverID, wafWhitelist); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf whitelist rules")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/blacklist") {
			serverID, ruleID, isBatch, ok := parseWafBlacklistPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafBlacklist.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load blacklist rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafBlacklistBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafBlacklist.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					if err := callL7UpdateBlacklist(r.Context(), servers, serverID, wafBlacklist); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf blacklist rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafBlacklistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafBlacklist.Create(r.Context(), serverID, store.WafBlacklistInput{
					IPs:         strings.TrimSpace(payload.IPs),
					URL:         strings.TrimSpace(payload.URL),
					Method:      strings.TrimSpace(payload.Method),
					Behavior:    strings.TrimSpace(payload.Behavior),
					Description: strings.TrimSpace(payload.Description),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create blacklist rule")
					return
				}
				if err := callL7UpdateBlacklist(r.Context(), servers, serverID, wafBlacklist); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf blacklist rules")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafBlacklistPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafBlacklist.Update(r.Context(), serverID, ruleID, store.WafBlacklistInput{
					IPs:         strings.TrimSpace(payload.IPs),
					URL:         strings.TrimSpace(payload.URL),
					Method:      strings.TrimSpace(payload.Method),
					Behavior:    strings.TrimSpace(payload.Behavior),
					Description: strings.TrimSpace(payload.Description),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "blacklist rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update blacklist rule")
					return
				}
				if err := callL7UpdateBlacklist(r.Context(), servers, serverID, wafBlacklist); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf blacklist rules")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafBlacklist.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete blacklist rule")
					return
				}
				if err := callL7UpdateBlacklist(r.Context(), servers, serverID, wafBlacklist); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf blacklist rules")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/geolocation") {
			serverID, ruleID, isBatch, ok := parseWafGeoPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafGeo.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load geo rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafGeoBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafGeo.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					if err := callL7UpdateGeo(r.Context(), servers, serverID, wafGeo); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf geo rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafGeoPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafGeo.Create(r.Context(), serverID, store.WafGeoInput{
					Country:   strings.TrimSpace(payload.Country),
					URL:       strings.TrimSpace(payload.URL),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Operation: strings.TrimSpace(payload.Operation),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create geo rule")
					return
				}
				if err := callL7UpdateGeo(r.Context(), servers, serverID, wafGeo); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf geo rules")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafGeoPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafGeo.Update(r.Context(), serverID, ruleID, store.WafGeoInput{
					Country:   strings.TrimSpace(payload.Country),
					URL:       strings.TrimSpace(payload.URL),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Operation: strings.TrimSpace(payload.Operation),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "geo rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update geo rule")
					return
				}
				if err := callL7UpdateGeo(r.Context(), servers, serverID, wafGeo); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf geo rules")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafGeo.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete geo rule")
					return
				}
				if err := callL7UpdateGeo(r.Context(), servers, serverID, wafGeo); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf geo rules")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/anti-cc") {
			serverID, ruleID, isBatch, ok := parseWafAntiCcPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafAntiCc.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load anti-cc rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafAntiCcBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafAntiCc.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafAntiCcPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafAntiCc.Create(r.Context(), serverID, store.WafAntiCcInput{
					URL:       strings.TrimSpace(payload.URL),
					Method:    strings.TrimSpace(payload.Method),
					Threshold: payload.Threshold,
					Window:    payload.Window,
					Action:    strings.TrimSpace(payload.Action),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create anti-cc rule")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafAntiCcPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafAntiCc.Update(r.Context(), serverID, ruleID, store.WafAntiCcInput{
					URL:       strings.TrimSpace(payload.URL),
					Method:    strings.TrimSpace(payload.Method),
					Threshold: payload.Threshold,
					Window:    payload.Window,
					Action:    strings.TrimSpace(payload.Action),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "anti-cc rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update anti-cc rule")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafAntiCc.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete anti-cc rule")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}
		if strings.Contains(r.URL.Path, "/waf/anti-header") {
			serverID, ruleID, isBatch, ok := parseWafAntiHeaderPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafAntiHeader.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load anti-header rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafAntiHeaderBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafAntiHeader.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					if err := callL7UpdateAntiHeader(r.Context(), servers, serverID, wafAntiHeader); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf anti-header rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafAntiHeaderPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafAntiHeader.Create(r.Context(), serverID, store.WafAntiHeaderInput{
					URL:       strings.TrimSpace(payload.URL),
					Header:    strings.TrimSpace(payload.Header),
					Value:     strings.TrimSpace(payload.Value),
					BlockMode: strings.TrimSpace(payload.BlockMode),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create anti-header rule")
					return
				}
				if err := callL7UpdateAntiHeader(r.Context(), servers, serverID, wafAntiHeader); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf anti-header rules")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafAntiHeaderPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafAntiHeader.Update(r.Context(), serverID, ruleID, store.WafAntiHeaderInput{
					URL:       strings.TrimSpace(payload.URL),
					Header:    strings.TrimSpace(payload.Header),
					Value:     strings.TrimSpace(payload.Value),
					BlockMode: strings.TrimSpace(payload.BlockMode),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "anti-header rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update anti-header rule")
					return
				}
				if err := callL7UpdateAntiHeader(r.Context(), servers, serverID, wafAntiHeader); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf anti-header rules")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafAntiHeader.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete anti-header rule")
					return
				}
				if err := callL7UpdateAntiHeader(r.Context(), servers, serverID, wafAntiHeader); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf anti-header rules")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/interval-freq-limit") {
			serverID, ruleID, isBatch, ok := parseWafIntervalPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafInterval.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load interval rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafIntervalBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafInterval.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					if err := callL7UpdateIntervalFreqLimit(r.Context(), servers, serverID, wafInterval); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf interval-freq-limit rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafIntervalPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafInterval.Create(r.Context(), serverID, store.WafIntervalInput{
					URL:          strings.TrimSpace(payload.URL),
					TimeSeconds:  payload.Time,
					RequestCount: payload.RequestCount,
					Behavior:     strings.TrimSpace(payload.Behavior),
					Status:       strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create interval rule")
					return
				}
				if err := callL7UpdateIntervalFreqLimit(r.Context(), servers, serverID, wafInterval); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf interval-freq-limit rules")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafIntervalPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafInterval.Update(r.Context(), serverID, ruleID, store.WafIntervalInput{
					URL:          strings.TrimSpace(payload.URL),
					TimeSeconds:  payload.Time,
					RequestCount: payload.RequestCount,
					Behavior:     strings.TrimSpace(payload.Behavior),
					Status:       strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "interval rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update interval rule")
					return
				}
				if err := callL7UpdateIntervalFreqLimit(r.Context(), servers, serverID, wafInterval); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf interval-freq-limit rules")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafInterval.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete interval rule")
					return
				}
				if err := callL7UpdateIntervalFreqLimit(r.Context(), servers, serverID, wafInterval); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf interval-freq-limit rules")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/second-freq-limit") {
			serverID, ruleID, isBatch, ok := parseWafSecondPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafSecond.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load second freq rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafSecondBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafSecond.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					if err := callL7UpdateSecondFreqLimit(r.Context(), servers, serverID, wafSecond); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf second-freq-limit rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafSecondPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafSecond.Create(r.Context(), serverID, store.WafSecondInput{
					URL:          strings.TrimSpace(payload.URL),
					RequestCount: payload.RequestCount,
					Burst:        payload.Burst,
					Behavior:     strings.TrimSpace(payload.Behavior),
					Status:       strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create second freq rule")
					return
				}
				if err := callL7UpdateSecondFreqLimit(r.Context(), servers, serverID, wafSecond); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf second-freq-limit rules")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafSecondPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafSecond.Update(r.Context(), serverID, ruleID, store.WafSecondInput{
					URL:          strings.TrimSpace(payload.URL),
					RequestCount: payload.RequestCount,
					Burst:        payload.Burst,
					Behavior:     strings.TrimSpace(payload.Behavior),
					Status:       strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "second freq rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update second freq rule")
					return
				}
				if err := callL7UpdateSecondFreqLimit(r.Context(), servers, serverID, wafSecond); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf second-freq-limit rules")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafSecond.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete second freq rule")
					return
				}
				if err := callL7UpdateSecondFreqLimit(r.Context(), servers, serverID, wafSecond); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf second-freq-limit rules")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/response-freq") {
			serverID, ruleID, isBatch, ok := parseWafResponsePath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafResponse.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load response freq rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafResponseBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafResponse.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					if err := callL7UpdateResponseFreq(r.Context(), servers, serverID, wafResponse); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf response-freq rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafResponsePayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafResponse.Create(r.Context(), serverID, store.WafResponseInput{
					URL:           strings.TrimSpace(payload.URL),
					ResponseCode:  strings.TrimSpace(payload.ResponseCode),
					TimeSeconds:   payload.Time,
					ResponseCount: payload.ResponseCount,
					Behavior:      strings.TrimSpace(payload.Behavior),
					Status:        strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create response freq rule")
					return
				}
				if err := callL7UpdateResponseFreq(r.Context(), servers, serverID, wafResponse); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf response-freq rules")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafResponsePayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafResponse.Update(r.Context(), serverID, ruleID, store.WafResponseInput{
					URL:           strings.TrimSpace(payload.URL),
					ResponseCode:  strings.TrimSpace(payload.ResponseCode),
					TimeSeconds:   payload.Time,
					ResponseCount: payload.ResponseCount,
					Behavior:      strings.TrimSpace(payload.Behavior),
					Status:        strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "response freq rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update response freq rule")
					return
				}
				if err := callL7UpdateResponseFreq(r.Context(), servers, serverID, wafResponse); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf response-freq rules")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafResponse.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete response freq rule")
					return
				}
				if err := callL7UpdateResponseFreq(r.Context(), servers, serverID, wafResponse); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf response-freq rules")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/waf/user-agent") {
			serverID, ruleID, isBatch, ok := parseWafUserAgentPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := wafUserAgent.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load user agent rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload wafUserAgentBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if err := wafUserAgent.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete rules")
						return
					}
					if err := callL7UpdateUserAgent(r.Context(), servers, serverID, wafUserAgent); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf user-agent rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload wafUserAgentPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				created, err := wafUserAgent.Create(r.Context(), serverID, store.WafUserAgentInput{
					URL:       strings.TrimSpace(payload.URL),
					UserAgent: strings.TrimSpace(payload.UserAgent),
					Match:     strings.TrimSpace(payload.Match),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create user agent rule")
					return
				}
				if err := callL7UpdateUserAgent(r.Context(), servers, serverID, wafUserAgent); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf user-agent rules")
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload wafUserAgentPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				updated, err := wafUserAgent.Update(r.Context(), serverID, ruleID, store.WafUserAgentInput{
					URL:       strings.TrimSpace(payload.URL),
					UserAgent: strings.TrimSpace(payload.UserAgent),
					Match:     strings.TrimSpace(payload.Match),
					Behavior:  strings.TrimSpace(payload.Behavior),
					Status:    strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "user agent rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update user agent rule")
					return
				}
				if err := callL7UpdateUserAgent(r.Context(), servers, serverID, wafUserAgent); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf user-agent rules")
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := wafUserAgent.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete user agent rule")
					return
				}
				if err := callL7UpdateUserAgent(r.Context(), servers, serverID, wafUserAgent); err != nil {
					writeError(w, http.StatusBadGateway, "failed to sync waf user-agent rules")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.HasSuffix(r.URL.Path, "/listening-ports/bound") {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/listening-ports/bound")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if r.Method != http.MethodGet {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			handleServerBoundPorts(w, r, servers, serverID)
			return
		}

		if strings.Contains(r.URL.Path, "/listening-ports") {
			serverID, portID, isBatch, ok := parseListeningPortsPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if portID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := listeningPorts.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load listening ports")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload listeningPortBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					list, err := listeningPorts.ListByServer(r.Context(), serverID)
					if err != nil {
						writeError(w, http.StatusInternalServerError, "failed to load listening ports")
						return
					}
					deleteIDs := make(map[int64]struct{}, len(payload.IDs))
					for _, id := range payload.IDs {
						deleteIDs[id] = struct{}{}
					}
					remaining := make([]store.ListeningPort, 0, len(list))
					for _, port := range list {
						if _, ok := deleteIDs[port.ID]; ok {
							continue
						}
						remaining = append(remaining, port)
					}
					if err := postL7ListeningPorts(r.Context(), servers, serverID, listeningPortsToL7Payload(remaining)); err != nil {
						writeError(w, http.StatusBadGateway, err.Error())
						return
					}
					if err := listeningPorts.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete listening ports")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload listeningPortPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				if err := validateListeningPortAvailable(r.Context(), servers, listeningPorts, serverID, payload.Port, 0); err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				created, err := listeningPorts.Create(r.Context(), serverID, store.ListeningPortInput{
					Port:        payload.Port,
					Protocol:    strings.TrimSpace(payload.Protocol),
					Description: strings.TrimSpace(payload.Description),
					Status:      strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create listening port")
					return
				}
				if err := callL7UpdateListeningPorts(r.Context(), servers, serverID, listeningPorts); err != nil {
					_ = listeningPorts.Delete(r.Context(), serverID, created.ID)
					writeError(w, http.StatusBadGateway, err.Error())
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if portID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload listeningPortPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				existingList, err := listeningPorts.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load listening ports")
					return
				}
				var previous store.ListeningPort
				found := false
				for _, port := range existingList {
					if port.ID == portID {
						previous = port
						found = true
						break
					}
				}
				if !found {
					writeError(w, http.StatusNotFound, "listening port not found")
					return
				}
				if err := validateListeningPortAvailable(r.Context(), servers, listeningPorts, serverID, payload.Port, portID); err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				updated, err := listeningPorts.Update(r.Context(), serverID, portID, store.ListeningPortInput{
					Port:        payload.Port,
					Protocol:    strings.TrimSpace(payload.Protocol),
					Description: strings.TrimSpace(payload.Description),
					Status:      strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "listening port not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update listening port")
					return
				}
				if err := callL7UpdateListeningPorts(r.Context(), servers, serverID, listeningPorts); err != nil {
					_, _ = listeningPorts.Update(r.Context(), serverID, portID, store.ListeningPortInput{
						Port:        previous.Port,
						Protocol:    previous.Protocol,
						Description: previous.Description,
						Status:      previous.Status,
					})
					writeError(w, http.StatusBadGateway, err.Error())
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if portID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := listeningPorts.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load listening ports")
					return
				}
				remaining := make([]store.ListeningPort, 0, len(list))
				found := false
				for _, port := range list {
					if port.ID == portID {
						found = true
						continue
					}
					remaining = append(remaining, port)
				}
				if !found {
					writeError(w, http.StatusNotFound, "listening port not found")
					return
				}
				if err := postL7ListeningPorts(r.Context(), servers, serverID, listeningPortsToL7Payload(remaining)); err != nil {
					writeError(w, http.StatusBadGateway, err.Error())
					return
				}
				if err := listeningPorts.Delete(r.Context(), serverID, portID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete listening port")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.HasSuffix(r.URL.Path, "/cache-rules/clear-url-cache") && r.Method == http.MethodPost {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/cache-rules/clear-url-cache")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			var payload clearUrlCachePayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			matchType, validationErr := normalizeClearUrlCacheMatchType(payload.MatchType)
			if validationErr != "" {
				writeError(w, http.StatusBadRequest, validationErr)
				return
			}
			matchContent := strings.TrimSpace(payload.MatchContent)
			if validationErr := validateClearUrlCacheContent(matchType, matchContent); validationErr != "" {
				writeError(w, http.StatusBadRequest, validationErr)
				return
			}
			if err := postL7ClearUrlCache(r.Context(), servers, serverID, matchType, matchContent); err != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/cache-rules/clear-cache") && r.Method == http.MethodPost {
			serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/cache-rules/clear-cache")
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if err := postL7CacheClear(r.Context(), servers, serverID, "l7_clear_cache"); err != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if strings.Contains(r.URL.Path, "/cache-rules") {
			serverID, ruleID, isBatch, ok := parseCacheRulesPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if ruleID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := cacheRules.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load cache rules")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload cacheRuleBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					list, err := cacheRules.ListByServer(r.Context(), serverID)
					if err != nil {
						writeError(w, http.StatusInternalServerError, "failed to load cache rules")
						return
					}
					deleteIDs := make(map[int64]struct{}, len(payload.IDs))
					for _, id := range payload.IDs {
						deleteIDs[id] = struct{}{}
					}
					remaining := make([]store.CacheRule, 0, len(list))
					for _, rule := range list {
						if _, ok := deleteIDs[rule.ID]; ok {
							continue
						}
						remaining = append(remaining, rule)
					}
					if err := postL7CacheRules(r.Context(), servers, serverID, cacheRulesToL7Payload(remaining)); err != nil {
						writeError(w, http.StatusBadGateway, err.Error())
						return
					}
					if err := cacheRules.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete cache rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload cacheRulePayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				input, validationErr := cacheRulePayloadToInput(payload)
				if validationErr != "" {
					writeError(w, http.StatusBadRequest, validationErr)
					return
				}
				existingList, err := cacheRules.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load cache rules")
					return
				}
				if store.CacheRuleNameExists(existingList, input.RuleName, 0) {
					writeError(w, http.StatusBadRequest, "cache rule "+input.RuleName+" already exists")
					return
				}
				created, err := cacheRules.Create(r.Context(), serverID, input)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create cache rule")
					return
				}
				if err := callL7UpdateCacheRules(r.Context(), servers, serverID, cacheRules); err != nil {
					_ = cacheRules.Delete(r.Context(), serverID, created.ID)
					writeError(w, http.StatusBadGateway, err.Error())
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload cacheRulePayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				input, validationErr := cacheRulePayloadToInput(payload)
				if validationErr != "" {
					writeError(w, http.StatusBadRequest, validationErr)
					return
				}
				existingList, err := cacheRules.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load cache rules")
					return
				}
				var previous store.CacheRule
				found := false
				for _, rule := range existingList {
					if rule.ID == ruleID {
						previous = rule
						found = true
						break
					}
				}
				if !found {
					writeError(w, http.StatusNotFound, "cache rule not found")
					return
				}
				if store.CacheRuleNameExists(existingList, input.RuleName, ruleID) {
					writeError(w, http.StatusBadRequest, "cache rule "+input.RuleName+" already exists")
					return
				}
				updated, err := cacheRules.Update(r.Context(), serverID, ruleID, input)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "cache rule not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update cache rule")
					return
				}
				if err := callL7UpdateCacheRules(r.Context(), servers, serverID, cacheRules); err != nil {
					_, _ = cacheRules.Update(r.Context(), serverID, ruleID, store.CacheRuleInput{
						RuleName:         previous.RuleName,
						RuleType:         previous.RuleType,
						CachingTime:      previous.CachingTime,
						URL:              previous.URL,
						FileTypes:        previous.FileTypes,
						Priority:         previous.Priority,
						CacheSlice:       previous.CacheSlice,
						WithoutParameter: previous.WithoutParameter,
						CacheMode:        previous.CacheMode,
						Status:           previous.Status,
					})
					writeError(w, http.StatusBadGateway, err.Error())
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if ruleID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := cacheRules.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load cache rules")
					return
				}
				remaining := make([]store.CacheRule, 0, len(list))
				found := false
				for _, rule := range list {
					if rule.ID == ruleID {
						found = true
						continue
					}
					remaining = append(remaining, rule)
				}
				if !found {
					writeError(w, http.StatusNotFound, "cache rule not found")
					return
				}
				if err := postL7CacheRules(r.Context(), servers, serverID, cacheRulesToL7Payload(remaining)); err != nil {
					writeError(w, http.StatusBadGateway, err.Error())
					return
				}
				if err := cacheRules.Delete(r.Context(), serverID, ruleID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete cache rule")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if strings.Contains(r.URL.Path, "/upstream-servers") {
			serverID, upstreamID, isBatch, ok := parseUpstreamPath(r.URL.Path)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}

			switch r.Method {
			case http.MethodGet:
				if upstreamID != 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := upstreamServers.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load upstream servers")
					return
				}
				writeJSON(w, http.StatusOK, list)
			case http.MethodPost:
				if isBatch {
					var payload upstreamServerBatchPayload
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					list, err := upstreamServers.ListByServer(r.Context(), serverID)
					if err != nil {
						writeError(w, http.StatusInternalServerError, "failed to load upstream servers")
						return
					}
					deleteIDs := make(map[int64]struct{}, len(payload.IDs))
					for _, id := range payload.IDs {
						deleteIDs[id] = struct{}{}
					}
					remaining := make([]store.UpstreamServer, 0, len(list))
					for _, upstream := range list {
						if _, ok := deleteIDs[upstream.ID]; ok {
							continue
						}
						remaining = append(remaining, upstream)
					}
					if err := postL7UpstreamServers(r.Context(), servers, serverID, upstreamServersToL7Payload(remaining)); err != nil {
						writeError(w, http.StatusBadGateway, err.Error())
						return
					}
					if err := upstreamServers.DeleteBatch(r.Context(), serverID, payload.IDs); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete upstream servers")
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var payload upstreamServerPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				address := strings.TrimSpace(payload.Address)
				if address == "" {
					writeError(w, http.StatusBadRequest, "address is required")
					return
				}
				existingList, err := upstreamServers.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load upstream servers")
					return
				}
				if store.UpstreamAddressExists(existingList, address, 0) {
					writeError(w, http.StatusBadRequest, "upstream server "+address+" is already registered")
					return
				}
				created, err := upstreamServers.Create(r.Context(), serverID, store.UpstreamServerInput{
					Address:     address,
					Description: strings.TrimSpace(payload.Description),
					Status:      strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to create upstream server")
					return
				}
				if err := callL7UpdateUpstreamServers(r.Context(), servers, serverID, upstreamServers); err != nil {
					_ = upstreamServers.Delete(r.Context(), serverID, created.ID)
					writeError(w, http.StatusBadGateway, err.Error())
					return
				}
				writeJSON(w, http.StatusCreated, created)
			case http.MethodPut:
				if upstreamID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				var payload upstreamServerPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					writeError(w, http.StatusBadRequest, "invalid JSON body")
					return
				}
				existingList, err := upstreamServers.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load upstream servers")
					return
				}
				var previous store.UpstreamServer
				found := false
				for _, upstream := range existingList {
					if upstream.ID == upstreamID {
						previous = upstream
						found = true
						break
					}
				}
				if !found {
					writeError(w, http.StatusNotFound, "upstream server not found")
					return
				}
				address := strings.TrimSpace(payload.Address)
				if address == "" {
					writeError(w, http.StatusBadRequest, "address is required")
					return
				}
				if store.UpstreamAddressExists(existingList, address, upstreamID) {
					writeError(w, http.StatusBadRequest, "upstream server "+address+" is already registered")
					return
				}
				updated, err := upstreamServers.Update(r.Context(), serverID, upstreamID, store.UpstreamServerInput{
					Address:     address,
					Description: strings.TrimSpace(payload.Description),
					Status:      strings.TrimSpace(payload.Status),
				})
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "upstream server not found")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to update upstream server")
					return
				}
				if err := callL7UpdateUpstreamServers(r.Context(), servers, serverID, upstreamServers); err != nil {
					_, _ = upstreamServers.Update(r.Context(), serverID, upstreamID, store.UpstreamServerInput{
						Address:     previous.Address,
						Description: previous.Description,
						Status:      previous.Status,
					})
					writeError(w, http.StatusBadGateway, err.Error())
					return
				}
				writeJSON(w, http.StatusOK, updated)
			case http.MethodDelete:
				if upstreamID == 0 || isBatch {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				list, err := upstreamServers.ListByServer(r.Context(), serverID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load upstream servers")
					return
				}
				remaining := make([]store.UpstreamServer, 0, len(list))
				found := false
				for _, upstream := range list {
					if upstream.ID == upstreamID {
						found = true
						continue
					}
					remaining = append(remaining, upstream)
				}
				if !found {
					writeError(w, http.StatusNotFound, "upstream server not found")
					return
				}
				if err := postL7UpstreamServers(r.Context(), servers, serverID, upstreamServersToL7Payload(remaining)); err != nil {
					writeError(w, http.StatusBadGateway, err.Error())
					return
				}
				if err := upstreamServers.Delete(r.Context(), serverID, upstreamID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to delete upstream server")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		serverID, ok := parseID(r.URL.Path, "/servers/")
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		switch r.Method {
		case http.MethodPut:
			var payload serverUpdatePayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			if err := servers.Update(r.Context(), serverID, store.ServerInput{
				Name:        strings.TrimSpace(payload.Name),
				IP:          strings.TrimSpace(payload.IP),
				Status:      strings.TrimSpace(payload.Status),
				LicenseType: strings.TrimSpace(payload.LicenseType),
				LicenseFile: strings.TrimSpace(payload.LicenseFile),
				Version:     strings.TrimSpace(payload.Version),
				SSHUser:     strings.TrimSpace(payload.SSHUser),
				SSHPassword: strings.TrimSpace(payload.SSHPassword),
				SSHPort:     strings.TrimSpace(payload.SSHPort),
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to update server")
				return
			}
			view, err := servers.GetView(r.Context(), serverID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load server")
				return
			}
			writeJSON(w, http.StatusOK, view)
		case http.MethodDelete:
			if err := servers.Delete(r.Context(), serverID); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to delete server")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func parseWafWhitelistPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "whitelist" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseL4BlacklistPath(path string) (serverID int64, entryID int64, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false
	}
	if parts[1] != "l4" || parts[2] != "blacklist" {
		return 0, 0, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false
	}
	if len(parts) == 3 {
		return serverID, 0, true
	}
	if len(parts) == 4 {
		entryID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false
		}
		return serverID, entryID, true
	}
	return 0, 0, false
}

func parseL4WhitelistPath(path string) (serverID int64, entryID int64, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false
	}
	if parts[1] != "l4" || parts[2] != "whitelist" {
		return 0, 0, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false
	}
	if len(parts) == 3 {
		return serverID, 0, true
	}
	if len(parts) == 4 {
		entryID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false
		}
		return serverID, entryID, true
	}
	return 0, 0, false
}

func parseWafBlacklistPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "blacklist" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafGeoPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "geolocation" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafAntiCcPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "anti-cc" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafAntiHeaderPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "anti-header" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafIntervalPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "interval-freq-limit" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafSecondPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "second-freq-limit" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafResponsePath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "response-freq" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseWafUserAgentPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != "user-agent" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return serverID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseListeningPortsPath(path string) (serverID int64, portID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return 0, 0, false, false
	}
	if parts[1] != "listening-ports" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 2 {
		return serverID, 0, false, true
	}
	if len(parts) == 3 && parts[2] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 3 {
		portID, ok = parsePositiveInt(parts[2])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, portID, false, true
	}
	return 0, 0, false, false
}

func parseCacheRulesPath(path string) (serverID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return 0, 0, false, false
	}
	if parts[1] != "cache-rules" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 2 {
		return serverID, 0, false, true
	}
	if len(parts) == 3 && parts[2] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 3 {
		ruleID, ok = parsePositiveInt(parts[2])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, ruleID, false, true
	}
	return 0, 0, false, false
}

func parseUpstreamPath(path string) (serverID int64, upstreamID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return 0, 0, false, false
	}
	if parts[1] != "upstream-servers" {
		return 0, 0, false, false
	}
	serverID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 2 {
		return serverID, 0, false, true
	}
	if len(parts) == 3 && parts[2] == "batch-delete" {
		return serverID, 0, true, true
	}
	if len(parts) == 3 {
		upstreamID, ok = parsePositiveInt(parts[2])
		if !ok {
			return 0, 0, false, false
		}
		return serverID, upstreamID, false, true
	}
	return 0, 0, false, false
}

func usersHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			list, err := users.List(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load users")
				return
			}
			writeJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var payload store.UserInput
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			payload = payload.Normalize()
			if payload.Name == "" || payload.Email == "" {
				writeError(w, http.StatusBadRequest, "name and email are required")
				return
			}
			if !strings.EqualFold(payload.Role, "User") {
				payload.ServerIDs = nil
			}
			created, err := users.Create(r.Context(), payload)
			if err != nil {
				if store.IsDuplicateEmail(err) {
					writeError(w, http.StatusConflict, "email already exists")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to create user")
				return
			}
			if err := users.UpdateUserServers(r.Context(), created.ID, payload.ServerIDs); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to assign servers")
				return
			}
			created.ServerIDs = payload.ServerIDs
			writeJSON(w, http.StatusCreated, created)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func userHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseID(r.URL.Path, "/users/")
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}

		switch r.Method {
		case http.MethodPut, http.MethodPatch:
			var payload store.UserInput
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			payload = payload.Normalize()
			if payload.Name == "" || payload.Email == "" {
				writeError(w, http.StatusBadRequest, "name and email are required")
				return
			}
			if !strings.EqualFold(payload.Role, "User") {
				payload.ServerIDs = nil
			}
			updated, err := users.Update(r.Context(), id, payload)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "user not found")
					return
				}
				if store.IsDuplicateEmail(err) {
					writeError(w, http.StatusConflict, "email already exists")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to update user")
				return
			}
			if err := users.UpdateUserServers(r.Context(), id, payload.ServerIDs); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to assign servers")
				return
			}
			updated.ServerIDs = payload.ServerIDs
			writeJSON(w, http.StatusOK, updated)
		case http.MethodDelete:
			if err := users.Delete(r.Context(), id); err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "user not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to delete user")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}
