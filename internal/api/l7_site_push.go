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

func postL7ToSiteEdgeServers(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, apiPath string, buildBody func(edgeServerID int64, server store.ServerView) ([]byte, error)) error {
	if siteID == 0 {
		return fmt.Errorf("invalid site id")
	}
	edgeIDs, err := siteEdgeServerIDs(ctx, sites, siteID)
	if err != nil {
		return err
	}
	if len(edgeIDs) == 0 {
		return fmt.Errorf("site has no assigned edge servers")
	}
	for _, edgeID := range edgeIDs {
		server, err := servers.GetView(ctx, edgeID)
		if err != nil {
			return fmt.Errorf("load server view: %w", err)
		}
		body, err := buildBody(edgeID, server)
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
			return fmt.Errorf("l7 returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
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
		return json.Marshal(l7UpstreamServersUpdatePayload{ServerID: server.ID, Upstreams: upstreams})
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

func postL7ListeningPorts(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, ports []listeningPortPayloadL7) error {
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_listeningports", func(edgeID int64, server store.ServerView) ([]byte, error) {
		for i := range ports {
			ports[i].ServerID = server.ID
		}
		return json.Marshal(l7ListeningPortsUpdatePayload{ServerID: server.ID, ListeningPorts: ports})
	})
}

func callL7UpdateListeningPorts(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, listeningPorts store.ListeningPortStore) error {
	list, err := listeningPorts.ListBySite(ctx, siteID)
	if err != nil {
		return fmt.Errorf("load listening ports: %w", err)
	}
	return postL7ListeningPorts(ctx, servers, sites, siteID, listeningPortsToL7Payload(0, list))
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
		return json.Marshal(l7CompressUpdatePayload{ServerID: server.ID, Compress: payload})
	})
}

func postL7Compress(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, settings compressPayloadL7) error {
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_update_compress", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(l7CompressUpdatePayload{ServerID: server.ID, Compress: settings})
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
		return json.Marshal(l7CacheRulesUpdatePayload{ServerID: server.ID, CacheRules: rules})
	})
}

func callL7UpdateCacheRules(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, cacheRules store.CacheRuleStore) error {
	list, err := cacheRules.ListBySite(ctx, siteID)
	if err != nil {
		return fmt.Errorf("load cache rules: %w", err)
	}
	return postL7CacheRules(ctx, servers, sites, siteID, cacheRulesToL7Payload(0, list))
}

func postL7CacheClear(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, endpoint string) error {
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, endpoint, func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(map[string]any{"serverId": server.ID})
	})
}

func postL7ClearUrlCache(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64, matchType, matchContent string) error {
	return postL7ToSiteEdgeServers(ctx, servers, sites, siteID, "/API/L7/l7_clear_url_cache", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(map[string]any{
			"serverId":      server.ID,
			"match_type":    matchType,
			"match_content": matchContent,
		})
	})
}
