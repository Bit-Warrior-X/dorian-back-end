package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"vue-project-backend/internal/store"
)

type l7StatusError struct {
	Status int
	Body   string
}

func (e *l7StatusError) Error() string {
	if e == nil {
		return "l7 request failed"
	}
	body := strings.TrimSpace(e.Body)
	if body == "" || looksLikeHTML(body) {
		return fmt.Sprintf("l7 returned status %d", e.Status)
	}
	return fmt.Sprintf("l7 returned status %d: %s", e.Status, body)
}

func looksLikeHTML(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype")
}

type edgeSyncFailure struct {
	ServerID   int64
	ServerName string
	ServerIP   string
	Err        error
}

type edgeSyncServerInfo struct {
	ServerID int64  `json:"serverId"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Error    string `json:"error,omitempty"`
}

type edgeSyncReport struct {
	Succeeded []edgeSyncServerInfo `json:"succeeded"`
	Failed    []edgeSyncServerInfo `json:"failed"`
	Warnings  []edgeSyncServerInfo `json:"warnings"`
}

type siteDeleteResponse struct {
	Deleted  bool           `json:"deleted"`
	EdgeSync edgeSyncReport `json:"edgeSync"`
}

type siteMutationResponse struct {
	store.Site
	EdgeSync edgeSyncReport `json:"edgeSync"`
}

func (f edgeSyncFailure) format() string {
	label := strings.TrimSpace(f.ServerName)
	if label == "" {
		label = fmt.Sprintf("server #%d", f.ServerID)
	}
	ip := strings.TrimSpace(f.ServerIP)
	if ip != "" {
		return fmt.Sprintf("%s (%s): %v", label, ip, f.Err)
	}
	return fmt.Sprintf("%s: %v", label, f.Err)
}

func formatEdgeSyncFailures(failures []edgeSyncFailure) error {
	if len(failures) == 0 {
		return nil
	}
	parts := make([]string, 0, len(failures))
	for _, failure := range failures {
		parts = append(parts, failure.format())
	}
	return fmt.Errorf("edge sync failed for %d server(s): %s", len(failures), strings.Join(parts, "; "))
}

func edgeLabel(name string, id int64) string {
	label := strings.TrimSpace(name)
	if label == "" {
		return fmt.Sprintf("server #%d", id)
	}
	return label
}

func postL7ToSiteEdgeServersDetailed(
	ctx context.Context,
	servers store.ServerStore,
	sites store.SiteStore,
	siteID int64,
	apiPath string,
	buildBody func(edgeServerID int64, server store.ServerView) ([]byte, error),
) (edgeSyncReport, error) {
	report := edgeSyncReport{
		Succeeded: make([]edgeSyncServerInfo, 0),
		Failed:    make([]edgeSyncServerInfo, 0),
		Warnings:  make([]edgeSyncServerInfo, 0),
	}
	if siteID == 0 {
		return report, fmt.Errorf("invalid site id")
	}
	edgeIDs, err := siteEdgeServerIDs(ctx, sites, siteID)
	if err != nil {
		return report, err
	}
	if len(edgeIDs) == 0 {
		return report, nil
	}

	for _, edgeID := range edgeIDs {
		server, err := servers.GetView(ctx, edgeID)
		if err != nil {
			report.Failed = append(report.Failed, edgeSyncServerInfo{
				ServerID: edgeID,
				Name:     edgeLabel("", edgeID),
				Error:    fmt.Sprintf("load server view: %v", err),
			})
			continue
		}
		info := edgeSyncServerInfo{
			ServerID: server.ID,
			Name:     edgeLabel(server.Name, server.ID),
			IP:       strings.TrimSpace(server.IP),
		}
		if err := postL7ToLoadedServer(ctx, server, apiPath, buildBody); err != nil {
			info.Error = err.Error()
			report.Failed = append(report.Failed, info)
			continue
		}
		report.Succeeded = append(report.Succeeded, info)
	}
	return report, nil
}

func postL7ToSiteEdgeServers(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, apiPath string, buildBody func(edgeServerID int64, server store.ServerView) ([]byte, error)) error {
	report, err := postL7ToSiteEdgeServersDetailed(ctx, servers, sites, siteID, apiPath, buildBody)
	if err != nil {
		return err
	}
	if len(report.Failed) == 0 {
		return nil
	}
	failures := make([]edgeSyncFailure, 0, len(report.Failed))
	for _, item := range report.Failed {
		failures = append(failures, edgeSyncFailure{
			ServerID:   item.ServerID,
			ServerName: item.Name,
			ServerIP:   item.IP,
			Err:        fmt.Errorf("%s", item.Error),
		})
	}
	return formatEdgeSyncFailures(failures)
}

func postL7ToServer(ctx context.Context, servers store.ServerStore, serverID int64, apiPath string, buildBody func(edgeServerID int64, server store.ServerView) ([]byte, error)) error {
	if serverID == 0 {
		return fmt.Errorf("invalid server id")
	}
	server, err := servers.GetView(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load server view: %w", err)
	}
	return postL7ToLoadedServer(ctx, server, apiPath, buildBody)
}

func postL7ToLoadedServer(ctx context.Context, server store.ServerView, apiPath string, buildBody func(edgeServerID int64, server store.ServerView) ([]byte, error)) error {
	body, err := buildBody(server.ID, server)
	if err != nil {
		return err
	}
	url := "http://" + strings.TrimSpace(server.IP) + ":5000" + apiPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build l7 request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("l7 request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &l7StatusError{
			Status: resp.StatusCode,
			Body:   strings.TrimSpace(string(limited)),
		}
	}
	return nil
}

func siteWafRuleID(ctx context.Context, sites store.SiteStore, siteID int64) (int64, error) {
	site, err := sites.Get(ctx, siteID)
	if err != nil {
		return 0, err
	}
	if site.WafID == nil || *site.WafID == 0 {
		return 0, fmt.Errorf("site has no waf rule")
	}
	return *site.WafID, nil
}

func callL7UpdateWhitelist(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, wafWhitelist store.WafWhitelistStore) error {
	wafRuleID, err := siteWafRuleID(ctx, sites, siteID)
	if err != nil {
		return err
	}
	rules, err := wafWhitelist.ListByWafRule(ctx, wafRuleID)
	if err != nil {
		return fmt.Errorf("load waf whitelist rules: %w", err)
	}
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_whitelist", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(l7WhitelistUpdatePayload{
			ServerID: server.ID,
			SiteID:   siteID,
			ServerIP: strings.TrimSpace(server.IP),
			Rules:    rules,
		})
	})
}

func callL7UpdateBlacklist(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, wafBlacklist store.WafBlacklistStore) error {
	wafRuleID, err := siteWafRuleID(ctx, sites, siteID)
	if err != nil {
		return err
	}
	rules, err := wafBlacklist.ListByWafRule(ctx, wafRuleID)
	if err != nil {
		return fmt.Errorf("load waf blacklist rules: %w", err)
	}
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_blacklist", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(l7BlacklistUpdatePayload{
			ServerID: server.ID,
			SiteID:   siteID,
			ServerIP: strings.TrimSpace(server.IP),
			Rules:    rules,
		})
	})
}

func callL7UpdateGeo(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, wafGeo store.WafGeoStore) error {
	wafRuleID, err := siteWafRuleID(ctx, sites, siteID)
	if err != nil {
		return err
	}
	rules, err := wafGeo.ListByWafRule(ctx, wafRuleID)
	if err != nil {
		return fmt.Errorf("load waf geolocation rules: %w", err)
	}
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_geolocation", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(l7GeoUpdatePayload{
			ServerID: server.ID,
			SiteID:   siteID,
			ServerIP: strings.TrimSpace(server.IP),
			Rules:    rules,
		})
	})
}

func callL7UpdateAntiHeader(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, wafAntiHeader store.WafAntiHeaderStore) error {
	wafRuleID, err := siteWafRuleID(ctx, sites, siteID)
	if err != nil {
		return err
	}
	rules, err := wafAntiHeader.ListByWafRule(ctx, wafRuleID)
	if err != nil {
		return fmt.Errorf("load waf anti-header rules: %w", err)
	}
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_antiheader", func(edgeID int64, server store.ServerView) ([]byte, error) {
		enabled := make([]store.WafAntiHeaderRule, 0, len(rules))
		for _, rule := range rules {
			if !strings.EqualFold(strings.TrimSpace(rule.Status), "ENABLE") {
				continue
			}
			enabled = append(enabled, rule)
		}
		return json.Marshal(l7AntiHeaderUpdatePayload{
			ServerID: server.ID,
			SiteID:   siteID,
			ServerIP: strings.TrimSpace(server.IP),
			Rules:    enabled,
		})
	})
}

func callL7UpdateIntervalFreqLimit(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, wafInterval store.WafIntervalStore) error {
	wafRuleID, err := siteWafRuleID(ctx, sites, siteID)
	if err != nil {
		return err
	}
	allRules, err := wafInterval.ListByWafRule(ctx, wafRuleID)
	if err != nil {
		return fmt.Errorf("load waf interval rules: %w", err)
	}
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_intervalfreqlimit", func(edgeID int64, server store.ServerView) ([]byte, error) {
		enabled := make([]intervalFreqLimitRulePayload, 0, len(allRules))
		for _, rule := range allRules {
			if !strings.EqualFold(strings.TrimSpace(rule.Status), "ENABLE") {
				continue
			}
			enabled = append(enabled, intervalFreqLimitRulePayload{
				ID:           rule.ID,
				ServerID:     server.ID,
				URL:          rule.URL,
				TimeSeconds:  rule.TimeSeconds,
				RequestCount: rule.RequestCount,
				Behavior:     rule.Behavior,
				Status:       rule.Status,
			})
		}
		return json.Marshal(l7IntervalFreqLimitUpdatePayload{
			ServerID: server.ID,
			SiteID:   siteID,
			ServerIP: strings.TrimSpace(server.IP),
			Rules:    enabled,
		})
	})
}

func callL7UpdateSecondFreqLimit(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, wafSecond store.WafSecondStore) error {
	wafRuleID, err := siteWafRuleID(ctx, sites, siteID)
	if err != nil {
		return err
	}
	allRules, err := wafSecond.ListByWafRule(ctx, wafRuleID)
	if err != nil {
		return fmt.Errorf("load waf second freq rules: %w", err)
	}
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_secondfreqlimit", func(edgeID int64, server store.ServerView) ([]byte, error) {
		enabled := make([]secondFreqLimitRulePayload, 0, len(allRules))
		for _, rule := range allRules {
			if !strings.EqualFold(strings.TrimSpace(rule.Status), "ENABLE") {
				continue
			}
			enabled = append(enabled, secondFreqLimitRulePayload{
				ID:           rule.ID,
				ServerID:     server.ID,
				URL:          rule.URL,
				RequestCount: rule.RequestCount,
				Burst:        rule.Burst,
				Behavior:     rule.Behavior,
				Status:       rule.Status,
			})
		}
		return json.Marshal(l7SecondFreqLimitUpdatePayload{
			ServerID: server.ID,
			SiteID:   siteID,
			ServerIP: strings.TrimSpace(server.IP),
			Rules:    enabled,
		})
	})
}

func callL7UpdateResponseFreq(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, wafResponse store.WafResponseStore) error {
	wafRuleID, err := siteWafRuleID(ctx, sites, siteID)
	if err != nil {
		return err
	}
	allRules, err := wafResponse.ListByWafRule(ctx, wafRuleID)
	if err != nil {
		return fmt.Errorf("load waf response freq rules: %w", err)
	}
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_responsefreq", func(edgeID int64, server store.ServerView) ([]byte, error) {
		enabled := make([]responseFreqRulePayload, 0, len(allRules))
		for _, rule := range allRules {
			if !strings.EqualFold(strings.TrimSpace(rule.Status), "ENABLE") {
				continue
			}
			enabled = append(enabled, responseFreqRulePayload{
				ID:            rule.ID,
				ServerID:      server.ID,
				URL:           rule.URL,
				ResponseCode:  rule.ResponseCode,
				TimeSeconds:   rule.TimeSeconds,
				ResponseCount: rule.ResponseCount,
				Behavior:      rule.Behavior,
				Status:        rule.Status,
			})
		}
		return json.Marshal(l7ResponseFreqUpdatePayload{
			ServerID: server.ID,
			SiteID:   siteID,
			ServerIP: strings.TrimSpace(server.IP),
			Rules:    enabled,
		})
	})
}

func callL7UpdateUserAgent(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, wafUserAgent store.WafUserAgentStore) error {
	wafRuleID, err := siteWafRuleID(ctx, sites, siteID)
	if err != nil {
		return err
	}
	allRules, err := wafUserAgent.ListByWafRule(ctx, wafRuleID)
	if err != nil {
		return fmt.Errorf("load waf user-agent rules: %w", err)
	}
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_useragent", func(edgeID int64, server store.ServerView) ([]byte, error) {
		enabled := make([]userAgentRulePayload, 0, len(allRules))
		for _, rule := range allRules {
			if !strings.EqualFold(strings.TrimSpace(rule.Status), "ENABLE") {
				continue
			}
			enabled = append(enabled, userAgentRulePayload{
				ID:        rule.ID,
				ServerID:  server.ID,
				URL:       rule.URL,
				UserAgent: rule.UserAgent,
				Match:     rule.Match,
				Behavior:  rule.Behavior,
				Status:    rule.Status,
			})
		}
		return json.Marshal(l7UserAgentUpdatePayload{
			ServerID: server.ID,
			SiteID:   siteID,
			ServerIP: strings.TrimSpace(server.IP),
			Rules:    enabled,
		})
	})
}

func upstreamServersToL7Payload(edgeServerID int64, list []store.UpstreamServer) []upstreamServerPayloadL7 {
	upstreams := make([]upstreamServerPayloadL7, 0, len(list))
	for _, u := range list {
		upstreams = append(upstreams, upstreamServerPayloadL7{
			ID:          u.ID,
			ServerID:    edgeServerID,
			IpPort:      strings.TrimSpace(u.Address),
			Protocol:    store.NormalizeUpstreamProtocol(u.Protocol),
			Description: strings.TrimSpace(u.Description),
		})
	}
	return upstreams
}

func postL7UpstreamServers(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, upstreams []upstreamServerPayloadL7) error {
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_upstreamservers", func(edgeID int64, server store.ServerView) ([]byte, error) {
		for i := range upstreams {
			upstreams[i].ServerID = server.ID
		}
		return json.Marshal(l7UpstreamServersUpdatePayload{ServerID: server.ID, SiteID: siteID, Upstreams: upstreams})
	})
}

func callL7UpdateUpstreamServers(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, upstreamServers store.UpstreamServerStore) error {
	list, err := upstreamServers.ListBySite(ctx, siteID)
	if err != nil {
		return fmt.Errorf("load upstream servers: %w", err)
	}
	return postL7UpstreamServers(ctx, servers, sites, siteID, upstreamServersToL7Payload(0, list))
}

func listeningPortsToL7Payload(edgeServerID int64, list []store.ListeningPort) []listeningPortPayloadL7 {
	ports := make([]listeningPortPayloadL7, 0, len(list))
	for _, item := range list {
		ports = append(ports, listeningPortPayloadL7{
			ID:          item.ID,
			ServerID:    edgeServerID,
			Port:        item.Port,
			Protocol:    strings.TrimSpace(item.Protocol),
			Description: strings.TrimSpace(item.Description),
			Status:      strings.TrimSpace(item.Status),
		})
	}
	return ports
}

func splitListeningPortsByProtocol(edgeServerID int64, list []store.ListeningPort) (httpPorts, httpsPorts []listeningPortPayloadL7) {
	httpPorts = make([]listeningPortPayloadL7, 0)
	httpsPorts = make([]listeningPortPayloadL7, 0)
	for _, item := range listeningPortsToL7Payload(edgeServerID, list) {
		if strings.EqualFold(strings.TrimSpace(item.Protocol), "HTTPS") {
			httpsPorts = append(httpsPorts, item)
			continue
		}
		httpPorts = append(httpPorts, item)
	}
	return httpPorts, httpsPorts
}

func postL7ListeningPorts(ctx context.Context, servers store.ServerStore, serverID int64, ports []listeningPortPayloadL7) error {
	return postL7ToServer(ctx, servers, serverID, "/API/L7/l7_update_listeningports", func(edgeID int64, server store.ServerView) ([]byte, error) {
		for i := range ports {
			ports[i].ServerID = server.ID
		}
		return json.Marshal(l7ListeningPortsUpdatePayload{
			ServerID:       server.ID,
			ListeningPorts: ports,
		})
	})
}

func callL7UpdateListeningPorts(ctx context.Context, servers store.ServerStore, serverID int64, listeningPorts store.ListeningPortStore) error {
	list, err := listeningPorts.ListByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load listening ports: %w", err)
	}
	return postL7ListeningPorts(ctx, servers, serverID, listeningPortsToL7Payload(serverID, list))
}

func postL7SiteListeningPorts(ctx context.Context, servers store.ServerStore, serverID, siteID int64, ports []store.ListeningPort) error {
	if siteID == 0 {
		return fmt.Errorf("invalid site id")
	}
	return postL7ToServer(ctx, servers, serverID, "/API/L7/l7_update_site_listeningports", func(edgeID int64, server store.ServerView) ([]byte, error) {
		httpPorts, httpsPorts := splitListeningPortsByProtocol(server.ID, ports)
		return json.Marshal(l7SiteListeningPortsUpdatePayload{
			ServerID:   server.ID,
			SiteID:     siteID,
			HTTPPorts:  httpPorts,
			HTTPSPorts: httpsPorts,
		})
	})
}

func callL7UpdateCompress(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, compressSettings store.CompressStore) error {
	settings, err := compressSettings.GetOrCreateBySiteID(ctx, siteID)
	if err != nil {
		return fmt.Errorf("load compress settings: %w", err)
	}
	payload := compressPayloadL7{
		CSS: settings.CSS, HTML: settings.HTML, JS: settings.JS,
		Audio: settings.Audio, Font: settings.Font, Applications: settings.Applications,
	}
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_compress", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(l7CompressUpdatePayload{ServerID: server.ID, SiteID: siteID, Compress: payload})
	})
}

func postL7Compress(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, settings compressPayloadL7) error {
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_compress", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(l7CompressUpdatePayload{ServerID: server.ID, SiteID: siteID, Compress: settings})
	})
}

func cacheRulesToL7Payload(edgeServerID int64, list []store.CacheRule) []cacheRulePayloadL7 {
	rules := make([]cacheRulePayloadL7, 0, len(list))
	for _, item := range list {
		rules = append(rules, cacheRulePayloadL7{
			ID:               item.ID,
			ServerID:         edgeServerID,
			RuleName:         item.RuleName,
			RuleType:         item.RuleType,
			CachingTime:      item.CachingTime,
			URL:              item.URL,
			FileTypes:        item.FileTypes,
			Priority:         item.Priority,
			CacheSlice:       item.CacheSlice,
			WithoutParameter: item.WithoutParameter,
			CacheMode:        item.CacheMode,
			Status:           item.Status,
		})
	}
	return rules
}

func postL7CacheRules(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, rules []cacheRulePayloadL7) error {
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_cacherules", func(edgeID int64, server store.ServerView) ([]byte, error) {
		for i := range rules {
			rules[i].ServerID = server.ID
		}
		return json.Marshal(l7CacheRulesUpdatePayload{ServerID: server.ID, SiteID: siteID, CacheRules: rules})
	})
}

func callL7UpdateCacheRules(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, cacheRules store.CacheRuleStore) error {
	list, err := cacheRules.ListBySite(ctx, siteID)
	if err != nil {
		return fmt.Errorf("load cache rules: %w", err)
	}
	return postL7CacheRules(ctx, servers, sites, siteID, cacheRulesToL7Payload(0, list))
}

func postL7CacheClear(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64) error {
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_clear_cache", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(l7CacheActionPayload{
			ServerID: server.ID,
			SiteID:   siteID,
		})
	})
}

func postL7ClearUrlCache(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, matchType, matchContent string) error {
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_clear_url_cache", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(map[string]any{
			"serverId":      server.ID,
			"siteId":        siteID,
			"match_type":    matchType,
			"match_content": matchContent,
		})
	})
}

// l7SiteSSLPayload is the SSL block sent with a full site config push.
type l7SiteSSLPayload struct {
	SslType    string `json:"ssl_type"`
	SslCert    string `json:"ssl_cert"`
	SslCertKey string `json:"ssl_cert_key"`
}

// l7SiteWafRulesPayload groups all WAF sub-rule tables for a site's waf_rule_id.
type l7SiteWafRulesPayload struct {
	WafRuleID            int64                     `json:"waf_rule_id"`
	WafWhitelist         []store.WafWhitelistRule  `json:"waf_whitelist"`
	WafBlacklist         []store.WafBlacklistRule  `json:"waf_blacklist"`
	WafGeolocation       []store.WafGeoRule        `json:"waf_geolocation"`
	WafAntiCc            []store.WafAntiCcRule     `json:"waf_anticc"`
	WafAntiHeader        []store.WafAntiHeaderRule `json:"waf_antiheader"`
	WafIntervalFreqLimit []store.WafIntervalRule   `json:"waf_intervalfreqlimit"`
	WafSecondFreqLimit   []store.WafSecondRule     `json:"waf_secondfreqlimit"`
	WafResponseFreq      []store.WafResponseRule   `json:"waf_responsefreq"`
	WafUserAgent         []store.WafUserAgentRule  `json:"waf_useragent"`
}

// l7SiteConfigPayload is the full site configuration pushed to angelos on site create.
type l7SiteConfigPayload struct {
	ServerID           int64                      `json:"server_id"`
	SiteID             int64                      `json:"site_id"`
	Domain             string                     `json:"domain"`
	SSL                l7SiteSSLPayload           `json:"ssl"`
	WafRules           l7SiteWafRulesPayload      `json:"waf_rules"`
	CompressSettings   compressPayloadL7          `json:"compress_settings"`
	CacheRules      []cacheRulePayloadL7      `json:"cache_rules"`
	HTTPPorts       []listeningPortPayloadL7  `json:"http_ports"`
	HTTPSPorts      []listeningPortPayloadL7  `json:"https_ports"`
	UpstreamServers []upstreamServerPayloadL7 `json:"upstream_servers"`
}

type siteL7Stores struct {
	wafWhitelist       store.WafWhitelistStore
	wafBlacklist       store.WafBlacklistStore
	wafGeo             store.WafGeoStore
	wafAntiCc          store.WafAntiCcStore
	wafAntiHeader      store.WafAntiHeaderStore
	wafInterval        store.WafIntervalStore
	wafSecond          store.WafSecondStore
	wafResponse        store.WafResponseStore
	wafUserAgent       store.WafUserAgentStore
	upstreamServers    store.UpstreamServerStore
	cacheRules         store.CacheRuleStore
	compressSettings   store.CompressStore
	siteListeningPorts store.SiteListeningPortStore
}

func buildL7SiteWafRules(
	ctx context.Context,
	wafRuleID int64,
	deps siteL7Stores,
) (l7SiteWafRulesPayload, error) {
	out := l7SiteWafRulesPayload{
		WafRuleID:            wafRuleID,
		WafWhitelist:         []store.WafWhitelistRule{},
		WafBlacklist:         []store.WafBlacklistRule{},
		WafGeolocation:       []store.WafGeoRule{},
		WafAntiCc:            []store.WafAntiCcRule{},
		WafAntiHeader:        []store.WafAntiHeaderRule{},
		WafIntervalFreqLimit: []store.WafIntervalRule{},
		WafSecondFreqLimit:   []store.WafSecondRule{},
		WafResponseFreq:      []store.WafResponseRule{},
		WafUserAgent:         []store.WafUserAgentRule{},
	}
	if wafRuleID <= 0 {
		return out, nil
	}

	var err error
	if out.WafWhitelist, err = deps.wafWhitelist.ListByWafRule(ctx, wafRuleID); err != nil {
		return out, fmt.Errorf("load waf whitelist: %w", err)
	}
	if out.WafBlacklist, err = deps.wafBlacklist.ListByWafRule(ctx, wafRuleID); err != nil {
		return out, fmt.Errorf("load waf blacklist: %w", err)
	}
	if out.WafGeolocation, err = deps.wafGeo.ListByWafRule(ctx, wafRuleID); err != nil {
		return out, fmt.Errorf("load waf geolocation: %w", err)
	}
	if out.WafAntiCc, err = deps.wafAntiCc.ListByWafRule(ctx, wafRuleID); err != nil {
		return out, fmt.Errorf("load waf anticc: %w", err)
	}
	if out.WafAntiHeader, err = deps.wafAntiHeader.ListByWafRule(ctx, wafRuleID); err != nil {
		return out, fmt.Errorf("load waf antiheader: %w", err)
	}
	if out.WafIntervalFreqLimit, err = deps.wafInterval.ListByWafRule(ctx, wafRuleID); err != nil {
		return out, fmt.Errorf("load waf interval freq: %w", err)
	}
	if out.WafSecondFreqLimit, err = deps.wafSecond.ListByWafRule(ctx, wafRuleID); err != nil {
		return out, fmt.Errorf("load waf second freq: %w", err)
	}
	if out.WafResponseFreq, err = deps.wafResponse.ListByWafRule(ctx, wafRuleID); err != nil {
		return out, fmt.Errorf("load waf response freq: %w", err)
	}
	if out.WafUserAgent, err = deps.wafUserAgent.ListByWafRule(ctx, wafRuleID); err != nil {
		return out, fmt.Errorf("load waf user agent: %w", err)
	}
	return out, nil
}

func buildL7SiteConfigPayload(
	ctx context.Context,
	site store.Site,
	edgeServerID int64,
	deps siteL7Stores,
) (l7SiteConfigPayload, error) {
	wafRuleID := int64(0)
	if site.WafID != nil {
		wafRuleID = *site.WafID
	}
	wafRules, err := buildL7SiteWafRules(ctx, wafRuleID, deps)
	if err != nil {
		return l7SiteConfigPayload{}, err
	}

	compress, err := deps.compressSettings.GetOrCreateBySiteID(ctx, site.ID)
	if err != nil {
		return l7SiteConfigPayload{}, fmt.Errorf("load compress settings: %w", err)
	}

	cacheList, err := deps.cacheRules.ListBySite(ctx, site.ID)
	if err != nil {
		return l7SiteConfigPayload{}, fmt.Errorf("load cache rules: %w", err)
	}

	upstreamList, err := deps.upstreamServers.ListBySite(ctx, site.ID)
	if err != nil {
		return l7SiteConfigPayload{}, fmt.Errorf("load upstream servers: %w", err)
	}

	selectedPorts, err := deps.siteListeningPorts.ListSelectedForServer(ctx, site.ID, edgeServerID)
	if err != nil {
		return l7SiteConfigPayload{}, fmt.Errorf("load site listening ports: %w", err)
	}
	httpPorts, httpsPorts := splitListeningPortsByProtocol(edgeServerID, selectedPorts)

	return l7SiteConfigPayload{
		ServerID: edgeServerID,
		SiteID:   site.ID,
		Domain:   site.Domain,
		SSL: l7SiteSSLPayload{
			SslType:    site.SslType,
			SslCert:    site.SslCert,
			SslCertKey: site.SslCertKey,
		},
		WafRules:         wafRules,
		CompressSettings: compressSettingsToL7Payload(compress),
		CacheRules:       cacheRulesToL7Payload(edgeServerID, cacheList),
		HTTPPorts:        httpPorts,
		HTTPSPorts:       httpsPorts,
		UpstreamServers:  upstreamServersToL7Payload(edgeServerID, upstreamList),
	}, nil
}

// callL7UpdateSite pushes the full site configuration to every assigned edge
// server via POST /API/L7/l7_update_site. Returns per-edge success/failure details.
// No-op (empty report) when the site has no servers.
func callL7UpdateSite(
	ctx context.Context,
	servers store.ServerStore,
	sites store.SiteStore,
	siteID int64,
	deps siteL7Stores,
) (edgeSyncReport, error) {
	report := edgeSyncReport{
		Succeeded: make([]edgeSyncServerInfo, 0),
		Failed:    make([]edgeSyncServerInfo, 0),
		Warnings:  make([]edgeSyncServerInfo, 0),
	}
	if siteID == 0 {
		return report, fmt.Errorf("invalid site id")
	}
	site, err := sites.Get(ctx, siteID)
	if err != nil {
		return report, fmt.Errorf("load site: %w", err)
	}
	if len(site.ServerIDs) == 0 {
		return report, nil
	}
	return postL7ToSiteEdgeServersDetailed(ctx, servers, sites, siteID, "/API/L7/l7_update_site", func(edgeID int64, server store.ServerView) ([]byte, error) {
		payload, err := buildL7SiteConfigPayload(ctx, site, server.ID, deps)
		if err != nil {
			return nil, err
		}
		payload.ServerID = server.ID
		return json.Marshal(payload)
	})
}

// applySiteEdgeSync keeps only edges that synced successfully and clears
// listening-port bindings for failed edges.
func applySiteEdgeSync(
	ctx context.Context,
	sites store.SiteStore,
	siteListeningPorts store.SiteListeningPortStore,
	siteID int64,
	report edgeSyncReport,
) (store.Site, error) {
	succeededIDs := make([]int64, 0, len(report.Succeeded))
	for _, item := range report.Succeeded {
		succeededIDs = append(succeededIDs, item.ServerID)
	}
	failedIDs := make([]int64, 0, len(report.Failed))
	for _, item := range report.Failed {
		failedIDs = append(failedIDs, item.ServerID)
	}

	if err := sites.UpdateSiteServers(ctx, siteID, succeededIDs); err != nil {
		return store.Site{}, fmt.Errorf("update site servers after edge sync: %w", err)
	}
	if len(failedIDs) > 0 && siteListeningPorts != nil {
		if err := siteListeningPorts.DeleteForServers(ctx, siteID, failedIDs); err != nil {
			return store.Site{}, fmt.Errorf("clear listening ports for failed edges: %w", err)
		}
	}
	updated, err := sites.Get(ctx, siteID)
	if err != nil {
		return store.Site{}, err
	}
	return updated, nil
}

func siteResponseWithEdgeSync(site store.Site, report edgeSyncReport) siteMutationResponse {
	if report.Succeeded == nil {
		report.Succeeded = []edgeSyncServerInfo{}
	}
	if report.Failed == nil {
		report.Failed = []edgeSyncServerInfo{}
	}
	if report.Warnings == nil {
		report.Warnings = []edgeSyncServerInfo{}
	}
	return siteMutationResponse{
		Site:     site,
		EdgeSync: report,
	}
}

func sameSiteDomain(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func mergeEdgeSyncWarnings(into edgeSyncReport, extra edgeSyncReport) edgeSyncReport {
	if into.Succeeded == nil {
		into.Succeeded = []edgeSyncServerInfo{}
	}
	if into.Failed == nil {
		into.Failed = []edgeSyncServerInfo{}
	}
	if into.Warnings == nil {
		into.Warnings = []edgeSyncServerInfo{}
	}
	into.Warnings = append(into.Warnings, extra.Warnings...)
	return into
}

// l7SiteDeletePayload notifies angelos to remove a site from an edge server.
type l7SiteDeletePayload struct {
	ServerID int64  `json:"server_id"`
	SiteID   int64  `json:"site_id"`
	Domain   string `json:"domain"`
}

const outdatedAngelosDeleteWarning = "Angelos on this edge does not support site delete (outdated agent). The site was still removed from Dorian."

func classifyDeleteEdgeReport(report edgeSyncReport) edgeSyncReport {
	out := edgeSyncReport{
		Succeeded: append([]edgeSyncServerInfo{}, report.Succeeded...),
		Failed:    make([]edgeSyncServerInfo, 0),
		Warnings:  append([]edgeSyncServerInfo{}, report.Warnings...),
	}
	if out.Succeeded == nil {
		out.Succeeded = []edgeSyncServerInfo{}
	}
	for _, item := range report.Failed {
		if strings.Contains(item.Error, "l7 returned status 404") {
			item.Error = outdatedAngelosDeleteWarning
		} else if strings.TrimSpace(item.Error) != "" {
			item.Error = fmt.Sprintf("%s The site was still removed from Dorian.", strings.TrimSpace(item.Error))
		}
		out.Warnings = append(out.Warnings, item)
	}
	return out
}

// callL7DeleteSite asks every assigned edge server to drop the site via
// POST /API/L7/l7_delete_site. HTTP 404 from an outdated angelos is a warning,
// not a hard failure. Must be called before the site is removed from the database.
func callL7DeleteSite(
	ctx context.Context,
	servers store.ServerStore,
	sites store.SiteStore,
	siteID int64,
) (edgeSyncReport, error) {
	report := edgeSyncReport{
		Succeeded: make([]edgeSyncServerInfo, 0),
		Failed:    make([]edgeSyncServerInfo, 0),
		Warnings:  make([]edgeSyncServerInfo, 0),
	}
	if siteID == 0 {
		return report, fmt.Errorf("invalid site id")
	}
	site, err := sites.Get(ctx, siteID)
	if err != nil {
		return report, fmt.Errorf("load site: %w", err)
	}
	if len(site.ServerIDs) == 0 {
		return report, nil
	}
	raw, err := postL7ToSiteEdgeServersDetailed(ctx, servers, sites, siteID, "/API/L7/l7_delete_site", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(l7SiteDeletePayload{
			ServerID: server.ID,
			SiteID:   site.ID,
			Domain:   site.Domain,
		})
	})
	if err != nil {
		return report, err
	}
	return classifyDeleteEdgeReport(raw), nil
}

// l7SiteDomainUpdatePayload tells angelos to rename a site domain on an edge.
type l7SiteDomainUpdatePayload struct {
	ServerID  int64  `json:"server_id"`
	SiteID    int64  `json:"site_id"`
	OldDomain string `json:"old_domain"`
	NewDomain string `json:"new_domain"`
}

const outdatedAngelosDomainWarning = "Angelos on this edge does not support domain rename (outdated agent). The new domain was still saved in Dorian."

func classifyDomainEdgeReport(report edgeSyncReport) edgeSyncReport {
	out := edgeSyncReport{
		Succeeded: append([]edgeSyncServerInfo{}, report.Succeeded...),
		Failed:    make([]edgeSyncServerInfo, 0),
		Warnings:  append([]edgeSyncServerInfo{}, report.Warnings...),
	}
	if out.Succeeded == nil {
		out.Succeeded = []edgeSyncServerInfo{}
	}
	for _, item := range report.Failed {
		if strings.Contains(item.Error, "l7 returned status 404") {
			item.Error = outdatedAngelosDomainWarning
		} else if strings.TrimSpace(item.Error) != "" {
			item.Error = fmt.Sprintf("%s The new domain was still saved in Dorian.", strings.TrimSpace(item.Error))
		}
		out.Warnings = append(out.Warnings, item)
	}
	return out
}

// callL7UpdateDomain asks every assigned edge to rename the site hostname via
// POST /API/L7/l7_update_domain. No-op when the domain is unchanged. HTTP 404
// from an outdated angelos is a warning, not a hard failure.
func callL7UpdateDomain(
	ctx context.Context,
	servers store.ServerStore,
	sites store.SiteStore,
	siteID int64,
	oldDomain string,
	newDomain string,
) (edgeSyncReport, error) {
	report := edgeSyncReport{
		Succeeded: make([]edgeSyncServerInfo, 0),
		Failed:    make([]edgeSyncServerInfo, 0),
		Warnings:  make([]edgeSyncServerInfo, 0),
	}
	if siteID == 0 {
		return report, fmt.Errorf("invalid site id")
	}
	if sameSiteDomain(oldDomain, newDomain) {
		return report, nil
	}
	site, err := sites.Get(ctx, siteID)
	if err != nil {
		return report, fmt.Errorf("load site: %w", err)
	}
	if len(site.ServerIDs) == 0 {
		return report, nil
	}
	raw, err := postL7ToSiteEdgeServersDetailed(ctx, servers, sites, siteID, "/API/L7/l7_update_domain", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(l7SiteDomainUpdatePayload{
			ServerID:  server.ID,
			SiteID:    site.ID,
			OldDomain: strings.TrimSpace(oldDomain),
			NewDomain: strings.TrimSpace(newDomain),
		})
	})
	if err != nil {
		return report, err
	}
	return classifyDomainEdgeReport(raw), nil
}

