package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"vue-project-backend/internal/store"
)

func resolveSiteWafRuleID(
	ctx context.Context,
	sites store.SiteStore,
	wafRules store.WafRuleStore,
	siteID int64,
	method string,
) (int64, error) {
	if method == http.MethodGet {
		return sites.EnsureWafRule(ctx, siteID, wafRules)
	}
	return sites.WafRuleIDForWrite(ctx, siteID, wafRules)
}

func siteDetailHandler(
	sites store.SiteStore,
	wafRules store.WafRuleStore,
	servers store.ServerStore,
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
	cacheRules store.CacheRuleStore,
	compressSettings store.CompressStore,
	siteListeningPorts store.SiteListeningPortStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/sites/") && strings.Count(strings.Trim(path, "/"), "/") >= 2 {
			if strings.Contains(r.URL.Path, "/waf/fork") {
				trimmed := strings.TrimPrefix(path, "/sites/")
				parts := strings.Split(trimmed, "/")
				if len(parts) >= 3 && parts[1] == "waf" && parts[2] == "fork" {
					siteID, ok := parsePositiveInt(parts[0])
					if !ok {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					if r.Method != http.MethodPost {
						writeError(w, http.StatusMethodNotAllowed, "method not allowed")
						return
					}
					updated, err := sites.ForkPredefinedWafForSite(r.Context(), siteID, wafRules)
					if err != nil {
						if store.IsNotFound(err) {
							writeError(w, http.StatusNotFound, "site not found")
							return
						}
						if strings.Contains(err.Error(), "no waf rule to fork") {
							writeError(w, http.StatusBadRequest, err.Error())
							return
						}
						writeError(w, http.StatusInternalServerError, "failed to fork waf rule for site")
						return
					}
					writeJSON(w, http.StatusOK, updated)
					return
				}
			}

			if strings.Contains(r.URL.Path, "/waf/whitelist") {
				siteID, ruleID, isBatch, ok := parseWafWhitelistPath(r.URL.Path)
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}

				wafRuleID, err := resolveSiteWafRuleID(r.Context(), sites, wafRules, siteID, r.Method)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "site not found")
						return
					}
					if store.IsPredefinedWafRequiresFork(err) {
						writeError(w, http.StatusConflict, "predefined waf rule must be forked before editing")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to resolve waf rule")
					return
				}

				switch r.Method {
				case http.MethodGet:
					if ruleID != 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					list, err := wafWhitelist.ListByWafRule(r.Context(), wafRuleID)
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
						if err := wafWhitelist.DeleteBatch(r.Context(), wafRuleID, payload.IDs); err != nil {
							writeError(w, http.StatusInternalServerError, "failed to delete rules")
							return
						}
						if err := callL7UpdateWhitelist(r.Context(), servers, sites, siteID, wafWhitelist); err != nil {
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
					created, err := wafWhitelist.Create(r.Context(), wafRuleID, store.WafWhitelistInput{
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
					if err := callL7UpdateWhitelist(r.Context(), servers, sites, siteID, wafWhitelist); err != nil {
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
					updated, err := wafWhitelist.Update(r.Context(), wafRuleID, ruleID, store.WafWhitelistInput{
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
					if err := callL7UpdateWhitelist(r.Context(), servers, sites, siteID, wafWhitelist); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf whitelist rules")
						return
					}
					writeJSON(w, http.StatusOK, updated)
				case http.MethodDelete:
					if ruleID == 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					if err := wafWhitelist.Delete(r.Context(), wafRuleID, ruleID); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete whitelist rule")
						return
					}
					if err := callL7UpdateWhitelist(r.Context(), servers, sites, siteID, wafWhitelist); err != nil {
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
				siteID, ruleID, isBatch, ok := parseWafBlacklistPath(r.URL.Path)
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}

				wafRuleID, err := resolveSiteWafRuleID(r.Context(), sites, wafRules, siteID, r.Method)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "site not found")
						return
					}
					if store.IsPredefinedWafRequiresFork(err) {
						writeError(w, http.StatusConflict, "predefined waf rule must be forked before editing")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to resolve waf rule")
					return
				}

				switch r.Method {
				case http.MethodGet:
					if ruleID != 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					list, err := wafBlacklist.ListByWafRule(r.Context(), wafRuleID)
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
						if err := wafBlacklist.DeleteBatch(r.Context(), wafRuleID, payload.IDs); err != nil {
							writeError(w, http.StatusInternalServerError, "failed to delete rules")
							return
						}
						if err := callL7UpdateBlacklist(r.Context(), servers, sites, siteID, wafBlacklist); err != nil {
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
					created, err := wafBlacklist.Create(r.Context(), wafRuleID, store.WafBlacklistInput{
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
					if err := callL7UpdateBlacklist(r.Context(), servers, sites, siteID, wafBlacklist); err != nil {
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
					updated, err := wafBlacklist.Update(r.Context(), wafRuleID, ruleID, store.WafBlacklistInput{
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
					if err := callL7UpdateBlacklist(r.Context(), servers, sites, siteID, wafBlacklist); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf blacklist rules")
						return
					}
					writeJSON(w, http.StatusOK, updated)
				case http.MethodDelete:
					if ruleID == 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					if err := wafBlacklist.Delete(r.Context(), wafRuleID, ruleID); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete blacklist rule")
						return
					}
					if err := callL7UpdateBlacklist(r.Context(), servers, sites, siteID, wafBlacklist); err != nil {
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
				siteID, ruleID, isBatch, ok := parseWafGeoPath(r.URL.Path)
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}

				wafRuleID, err := resolveSiteWafRuleID(r.Context(), sites, wafRules, siteID, r.Method)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "site not found")
						return
					}
					if store.IsPredefinedWafRequiresFork(err) {
						writeError(w, http.StatusConflict, "predefined waf rule must be forked before editing")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to resolve waf rule")
					return
				}

				switch r.Method {
				case http.MethodGet:
					if ruleID != 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					list, err := wafGeo.ListByWafRule(r.Context(), wafRuleID)
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
						if err := wafGeo.DeleteBatch(r.Context(), wafRuleID, payload.IDs); err != nil {
							writeError(w, http.StatusInternalServerError, "failed to delete rules")
							return
						}
						if err := callL7UpdateGeo(r.Context(), servers, sites, siteID, wafGeo); err != nil {
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
					created, err := wafGeo.Create(r.Context(), wafRuleID, store.WafGeoInput{
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
					if err := callL7UpdateGeo(r.Context(), servers, sites, siteID, wafGeo); err != nil {
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
					updated, err := wafGeo.Update(r.Context(), wafRuleID, ruleID, store.WafGeoInput{
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
					if err := callL7UpdateGeo(r.Context(), servers, sites, siteID, wafGeo); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf geo rules")
						return
					}
					writeJSON(w, http.StatusOK, updated)
				case http.MethodDelete:
					if ruleID == 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					if err := wafGeo.Delete(r.Context(), wafRuleID, ruleID); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete geo rule")
						return
					}
					if err := callL7UpdateGeo(r.Context(), servers, sites, siteID, wafGeo); err != nil {
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
				siteID, ruleID, isBatch, ok := parseWafAntiCcPath(r.URL.Path)
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}

				wafRuleID, err := resolveSiteWafRuleID(r.Context(), sites, wafRules, siteID, r.Method)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "site not found")
						return
					}
					if store.IsPredefinedWafRequiresFork(err) {
						writeError(w, http.StatusConflict, "predefined waf rule must be forked before editing")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to resolve waf rule")
					return
				}

				switch r.Method {
				case http.MethodGet:
					if ruleID != 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					list, err := wafAntiCc.ListByWafRule(r.Context(), wafRuleID)
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
						if err := wafAntiCc.DeleteBatch(r.Context(), wafRuleID, payload.IDs); err != nil {
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
					created, err := wafAntiCc.Create(r.Context(), wafRuleID, store.WafAntiCcInput{
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
					updated, err := wafAntiCc.Update(r.Context(), wafRuleID, ruleID, store.WafAntiCcInput{
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
					if err := wafAntiCc.Delete(r.Context(), wafRuleID, ruleID); err != nil {
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
				siteID, ruleID, isBatch, ok := parseWafAntiHeaderPath(r.URL.Path)
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}

				wafRuleID, err := resolveSiteWafRuleID(r.Context(), sites, wafRules, siteID, r.Method)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "site not found")
						return
					}
					if store.IsPredefinedWafRequiresFork(err) {
						writeError(w, http.StatusConflict, "predefined waf rule must be forked before editing")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to resolve waf rule")
					return
				}

				switch r.Method {
				case http.MethodGet:
					if ruleID != 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					list, err := wafAntiHeader.ListByWafRule(r.Context(), wafRuleID)
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
						if err := wafAntiHeader.DeleteBatch(r.Context(), wafRuleID, payload.IDs); err != nil {
							writeError(w, http.StatusInternalServerError, "failed to delete rules")
							return
						}
						if err := callL7UpdateAntiHeader(r.Context(), servers, sites, siteID, wafAntiHeader); err != nil {
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
					created, err := wafAntiHeader.Create(r.Context(), wafRuleID, store.WafAntiHeaderInput{
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
					if err := callL7UpdateAntiHeader(r.Context(), servers, sites, siteID, wafAntiHeader); err != nil {
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
					updated, err := wafAntiHeader.Update(r.Context(), wafRuleID, ruleID, store.WafAntiHeaderInput{
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
					if err := callL7UpdateAntiHeader(r.Context(), servers, sites, siteID, wafAntiHeader); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf anti-header rules")
						return
					}
					writeJSON(w, http.StatusOK, updated)
				case http.MethodDelete:
					if ruleID == 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					if err := wafAntiHeader.Delete(r.Context(), wafRuleID, ruleID); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete anti-header rule")
						return
					}
					if err := callL7UpdateAntiHeader(r.Context(), servers, sites, siteID, wafAntiHeader); err != nil {
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
				siteID, ruleID, isBatch, ok := parseWafIntervalPath(r.URL.Path)
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}

				wafRuleID, err := resolveSiteWafRuleID(r.Context(), sites, wafRules, siteID, r.Method)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "site not found")
						return
					}
					if store.IsPredefinedWafRequiresFork(err) {
						writeError(w, http.StatusConflict, "predefined waf rule must be forked before editing")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to resolve waf rule")
					return
				}

				switch r.Method {
				case http.MethodGet:
					if ruleID != 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					list, err := wafInterval.ListByWafRule(r.Context(), wafRuleID)
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
						if err := wafInterval.DeleteBatch(r.Context(), wafRuleID, payload.IDs); err != nil {
							writeError(w, http.StatusInternalServerError, "failed to delete rules")
							return
						}
						if err := callL7UpdateIntervalFreqLimit(r.Context(), servers, sites, siteID, wafInterval); err != nil {
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
					created, err := wafInterval.Create(r.Context(), wafRuleID, store.WafIntervalInput{
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
					if err := callL7UpdateIntervalFreqLimit(r.Context(), servers, sites, siteID, wafInterval); err != nil {
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
					updated, err := wafInterval.Update(r.Context(), wafRuleID, ruleID, store.WafIntervalInput{
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
					if err := callL7UpdateIntervalFreqLimit(r.Context(), servers, sites, siteID, wafInterval); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf interval-freq-limit rules")
						return
					}
					writeJSON(w, http.StatusOK, updated)
				case http.MethodDelete:
					if ruleID == 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					if err := wafInterval.Delete(r.Context(), wafRuleID, ruleID); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete interval rule")
						return
					}
					if err := callL7UpdateIntervalFreqLimit(r.Context(), servers, sites, siteID, wafInterval); err != nil {
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
				siteID, ruleID, isBatch, ok := parseWafSecondPath(r.URL.Path)
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}

				wafRuleID, err := resolveSiteWafRuleID(r.Context(), sites, wafRules, siteID, r.Method)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "site not found")
						return
					}
					if store.IsPredefinedWafRequiresFork(err) {
						writeError(w, http.StatusConflict, "predefined waf rule must be forked before editing")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to resolve waf rule")
					return
				}

				switch r.Method {
				case http.MethodGet:
					if ruleID != 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					list, err := wafSecond.ListByWafRule(r.Context(), wafRuleID)
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
						if err := wafSecond.DeleteBatch(r.Context(), wafRuleID, payload.IDs); err != nil {
							writeError(w, http.StatusInternalServerError, "failed to delete rules")
							return
						}
						if err := callL7UpdateSecondFreqLimit(r.Context(), servers, sites, siteID, wafSecond); err != nil {
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
					created, err := wafSecond.Create(r.Context(), wafRuleID, store.WafSecondInput{
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
					if err := callL7UpdateSecondFreqLimit(r.Context(), servers, sites, siteID, wafSecond); err != nil {
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
					updated, err := wafSecond.Update(r.Context(), wafRuleID, ruleID, store.WafSecondInput{
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
					if err := callL7UpdateSecondFreqLimit(r.Context(), servers, sites, siteID, wafSecond); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf second-freq-limit rules")
						return
					}
					writeJSON(w, http.StatusOK, updated)
				case http.MethodDelete:
					if ruleID == 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					if err := wafSecond.Delete(r.Context(), wafRuleID, ruleID); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete second freq rule")
						return
					}
					if err := callL7UpdateSecondFreqLimit(r.Context(), servers, sites, siteID, wafSecond); err != nil {
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
				siteID, ruleID, isBatch, ok := parseWafResponsePath(r.URL.Path)
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}

				wafRuleID, err := resolveSiteWafRuleID(r.Context(), sites, wafRules, siteID, r.Method)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "site not found")
						return
					}
					if store.IsPredefinedWafRequiresFork(err) {
						writeError(w, http.StatusConflict, "predefined waf rule must be forked before editing")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to resolve waf rule")
					return
				}

				switch r.Method {
				case http.MethodGet:
					if ruleID != 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					list, err := wafResponse.ListByWafRule(r.Context(), wafRuleID)
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
						if err := wafResponse.DeleteBatch(r.Context(), wafRuleID, payload.IDs); err != nil {
							writeError(w, http.StatusInternalServerError, "failed to delete rules")
							return
						}
						if err := callL7UpdateResponseFreq(r.Context(), servers, sites, siteID, wafResponse); err != nil {
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
					created, err := wafResponse.Create(r.Context(), wafRuleID, store.WafResponseInput{
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
					if err := callL7UpdateResponseFreq(r.Context(), servers, sites, siteID, wafResponse); err != nil {
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
					updated, err := wafResponse.Update(r.Context(), wafRuleID, ruleID, store.WafResponseInput{
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
					if err := callL7UpdateResponseFreq(r.Context(), servers, sites, siteID, wafResponse); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf response-freq rules")
						return
					}
					writeJSON(w, http.StatusOK, updated)
				case http.MethodDelete:
					if ruleID == 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					if err := wafResponse.Delete(r.Context(), wafRuleID, ruleID); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete response freq rule")
						return
					}
					if err := callL7UpdateResponseFreq(r.Context(), servers, sites, siteID, wafResponse); err != nil {
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
				siteID, ruleID, isBatch, ok := parseWafUserAgentPath(r.URL.Path)
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}

				wafRuleID, err := resolveSiteWafRuleID(r.Context(), sites, wafRules, siteID, r.Method)
				if err != nil {
					if store.IsNotFound(err) {
						writeError(w, http.StatusNotFound, "site not found")
						return
					}
					if store.IsPredefinedWafRequiresFork(err) {
						writeError(w, http.StatusConflict, "predefined waf rule must be forked before editing")
						return
					}
					writeError(w, http.StatusInternalServerError, "failed to resolve waf rule")
					return
				}

				switch r.Method {
				case http.MethodGet:
					if ruleID != 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					list, err := wafUserAgent.ListByWafRule(r.Context(), wafRuleID)
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
						if err := wafUserAgent.DeleteBatch(r.Context(), wafRuleID, payload.IDs); err != nil {
							writeError(w, http.StatusInternalServerError, "failed to delete rules")
							return
						}
						if err := callL7UpdateUserAgent(r.Context(), servers, sites, siteID, wafUserAgent); err != nil {
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
					created, err := wafUserAgent.Create(r.Context(), wafRuleID, store.WafUserAgentInput{
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
					if err := callL7UpdateUserAgent(r.Context(), servers, sites, siteID, wafUserAgent); err != nil {
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
					updated, err := wafUserAgent.Update(r.Context(), wafRuleID, ruleID, store.WafUserAgentInput{
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
					if err := callL7UpdateUserAgent(r.Context(), servers, sites, siteID, wafUserAgent); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf user-agent rules")
						return
					}
					writeJSON(w, http.StatusOK, updated)
				case http.MethodDelete:
					if ruleID == 0 || isBatch {
						writeError(w, http.StatusNotFound, "not found")
						return
					}
					if err := wafUserAgent.Delete(r.Context(), wafRuleID, ruleID); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete user agent rule")
						return
					}
					if err := callL7UpdateUserAgent(r.Context(), servers, sites, siteID, wafUserAgent); err != nil {
						writeError(w, http.StatusBadGateway, "failed to sync waf user-agent rules")
						return
					}
					w.WriteHeader(http.StatusNoContent)
				default:
					writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				}
				return
			}

			if strings.HasSuffix(r.URL.Path, "/ports") {
				siteID, ok := parseIDWithSuffix(r.URL.Path, "/sites/", "/ports")
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				switch r.Method {
				case http.MethodGet:
					config, err := loadSitePortsConfig(r.Context(), sites, servers, siteListeningPorts, siteID)
					if err != nil {
						if store.IsNotFound(err) {
							writeError(w, http.StatusNotFound, "site not found")
							return
						}
						writeError(w, http.StatusInternalServerError, "failed to load site ports")
						return
					}
					writeJSON(w, http.StatusOK, config)
				case http.MethodPut:
					var payload struct {
						ServerID     int64   `json:"serverId"`
						HTTPPortIDs  []int64 `json:"httpPortIds"`
						HTTPSPortIDs []int64 `json:"httpsPortIds"`
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					if payload.ServerID <= 0 {
						writeError(w, http.StatusBadRequest, "serverId is required")
						return
					}
					site, err := sites.Get(r.Context(), siteID)
					if err != nil {
						if store.IsNotFound(err) {
							writeError(w, http.StatusNotFound, "site not found")
							return
						}
						writeError(w, http.StatusInternalServerError, "failed to load site")
						return
					}
					assigned := false
					for _, id := range site.ServerIDs {
						if id == payload.ServerID {
							assigned = true
							break
						}
					}
					if !assigned {
						writeError(w, http.StatusBadRequest, "server is not assigned to this site")
						return
					}
					mergedIDs, validationErr := validateSitePortSelections(r.Context(), siteListeningPorts, payload.ServerID, payload.HTTPPortIDs, payload.HTTPSPortIDs)
					if validationErr != "" {
						writeError(w, http.StatusBadRequest, validationErr)
						return
					}
					if err := siteListeningPorts.ReplaceForServer(r.Context(), siteID, payload.ServerID, mergedIDs); err != nil {
						writeError(w, http.StatusBadRequest, err.Error())
						return
					}
					config, err := loadSitePortsConfig(r.Context(), sites, servers, siteListeningPorts, siteID)
					if err != nil {
						writeError(w, http.StatusInternalServerError, "failed to load site ports")
						return
					}
					writeJSON(w, http.StatusOK, config)
				default:
					writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				}
				return
			}

			if strings.HasSuffix(r.URL.Path, "/compress") {
				siteID, ok := parseIDWithSuffix(r.URL.Path, "/sites/", "/compress")
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				switch r.Method {
				case http.MethodGet:
					settings, err := compressSettings.GetOrCreateBySiteID(r.Context(), siteID)
					if err != nil {
						if store.IsNotFound(err) {
							writeError(w, http.StatusNotFound, "server not found")
							return
						}
						writeError(w, http.StatusInternalServerError, "failed to load compress settings")
						return
					}
					writeJSON(w, http.StatusOK, settings)
				case http.MethodPut:
					var payload store.CompressSettings
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						writeError(w, http.StatusBadRequest, "invalid JSON body")
						return
					}
					input := store.CompressSettingsInput{
						CSS:          payload.CSS,
						HTML:         payload.HTML,
						JS:           payload.JS,
						Audio:        payload.Audio,
						Font:         payload.Font,
						Applications: payload.Applications,
					}
					previous, err := compressSettings.GetOrCreateBySiteID(r.Context(), siteID)
					if err != nil {
						if store.IsNotFound(err) {
							writeError(w, http.StatusNotFound, "server not found")
							return
						}
						writeError(w, http.StatusInternalServerError, "failed to load compress settings")
						return
					}
					if err := postL7Compress(r.Context(), servers, sites, siteID, compressSettingsToL7Payload(store.CompressSettings{
						CSS:          input.CSS,
						HTML:         input.HTML,
						JS:           input.JS,
						Audio:        input.Audio,
						Font:         input.Font,
						Applications: input.Applications,
					})); err != nil {
						writeError(w, http.StatusBadGateway, err.Error())
						return
					}
					updated, err := compressSettings.UpsertBySiteID(r.Context(), siteID, input)
					if err != nil {
						_, _ = compressSettings.UpsertBySiteID(r.Context(), siteID, store.CompressSettingsInput{
							CSS:          previous.CSS,
							HTML:         previous.HTML,
							JS:           previous.JS,
							Audio:        previous.Audio,
							Font:         previous.Font,
							Applications: previous.Applications,
						})
						if store.IsNotFound(err) {
							writeError(w, http.StatusNotFound, "server not found")
							return
						}
						writeError(w, http.StatusInternalServerError, "failed to update compress settings")
						return
					}
					writeJSON(w, http.StatusOK, updated)
				default:
					writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				}
				return
			}

			if strings.HasSuffix(r.URL.Path, "/cache-rules/clear-url-cache") && r.Method == http.MethodPost {
				siteID, ok := parseIDWithSuffix(r.URL.Path, "/sites/", "/cache-rules/clear-url-cache")
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
				if err := postL7ClearUrlCache(r.Context(), servers, sites, siteID, matchType, matchContent); err != nil {
					writeError(w, http.StatusBadGateway, err.Error())
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			if strings.HasSuffix(r.URL.Path, "/cache-rules/clear-cache") && r.Method == http.MethodPost {
				siteID, ok := parseIDWithSuffix(r.URL.Path, "/sites/", "/cache-rules/clear-cache")
				if !ok {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				if err := postL7CacheClear(r.Context(), servers, sites, siteID, "l7_clear_cache"); err != nil {
					writeError(w, http.StatusBadGateway, err.Error())
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			if strings.Contains(r.URL.Path, "/cache-rules") {
				siteID, ruleID, isBatch, ok := parseCacheRulesPath(r.URL.Path)
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
					list, err := cacheRules.ListBySite(r.Context(), siteID)
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
						list, err := cacheRules.ListBySite(r.Context(), siteID)
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
						if err := postL7CacheRules(r.Context(), servers, sites, siteID, cacheRulesToL7Payload(0, remaining)); err != nil {
							writeError(w, http.StatusBadGateway, err.Error())
							return
						}
						if err := cacheRules.DeleteBatch(r.Context(), siteID, payload.IDs); err != nil {
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
					existingList, err := cacheRules.ListBySite(r.Context(), siteID)
					if err != nil {
						writeError(w, http.StatusInternalServerError, "failed to load cache rules")
						return
					}
					if store.CacheRuleNameExists(existingList, input.RuleName, 0) {
						writeError(w, http.StatusBadRequest, "cache rule "+input.RuleName+" already exists")
						return
					}
					created, err := cacheRules.Create(r.Context(), siteID, input)
					if err != nil {
						if store.IsNotFound(err) {
							writeError(w, http.StatusNotFound, "server not found")
							return
						}
						writeError(w, http.StatusInternalServerError, "failed to create cache rule")
						return
					}
					if err := callL7UpdateCacheRules(r.Context(), servers, sites, siteID, cacheRules); err != nil {
						_ = cacheRules.Delete(r.Context(), siteID, created.ID)
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
					existingList, err := cacheRules.ListBySite(r.Context(), siteID)
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
					updated, err := cacheRules.Update(r.Context(), siteID, ruleID, input)
					if err != nil {
						if store.IsNotFound(err) {
							writeError(w, http.StatusNotFound, "cache rule not found")
							return
						}
						writeError(w, http.StatusInternalServerError, "failed to update cache rule")
						return
					}
					if err := callL7UpdateCacheRules(r.Context(), servers, sites, siteID, cacheRules); err != nil {
						_, _ = cacheRules.Update(r.Context(), siteID, ruleID, store.CacheRuleInput{
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
					list, err := cacheRules.ListBySite(r.Context(), siteID)
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
					if err := postL7CacheRules(r.Context(), servers, sites, siteID, cacheRulesToL7Payload(0, remaining)); err != nil {
						writeError(w, http.StatusBadGateway, err.Error())
						return
					}
					if err := cacheRules.Delete(r.Context(), siteID, ruleID); err != nil {
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
				siteID, upstreamID, isBatch, ok := parseUpstreamPath(r.URL.Path)
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
					list, err := upstreamServers.ListBySite(r.Context(), siteID)
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
						list, err := upstreamServers.ListBySite(r.Context(), siteID)
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
						if err := postL7UpstreamServers(r.Context(), servers, sites, siteID, upstreamServersToL7Payload(0, remaining)); err != nil {
							writeError(w, http.StatusBadGateway, err.Error())
							return
						}
						if err := upstreamServers.DeleteBatch(r.Context(), siteID, payload.IDs); err != nil {
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
					existingList, err := upstreamServers.ListBySite(r.Context(), siteID)
					if err != nil {
						writeError(w, http.StatusInternalServerError, "failed to load upstream servers")
						return
					}
					if store.UpstreamAddressExists(existingList, address, 0) {
						writeError(w, http.StatusBadRequest, "upstream server "+address+" is already registered")
						return
					}
					created, err := upstreamServers.Create(r.Context(), siteID, store.UpstreamServerInput{
						Address:     address,
						Protocol:    strings.TrimSpace(payload.Protocol),
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
					if err := callL7UpdateUpstreamServers(r.Context(), servers, sites, siteID, upstreamServers); err != nil {
						_ = upstreamServers.Delete(r.Context(), siteID, created.ID)
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
					existingList, err := upstreamServers.ListBySite(r.Context(), siteID)
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
					updated, err := upstreamServers.Update(r.Context(), siteID, upstreamID, store.UpstreamServerInput{
						Address:     address,
						Protocol:    strings.TrimSpace(payload.Protocol),
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
					if err := callL7UpdateUpstreamServers(r.Context(), servers, sites, siteID, upstreamServers); err != nil {
						_, _ = upstreamServers.Update(r.Context(), siteID, upstreamID, store.UpstreamServerInput{
							Address:     previous.Address,
							Protocol:    previous.Protocol,
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
					list, err := upstreamServers.ListBySite(r.Context(), siteID)
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
					if err := postL7UpstreamServers(r.Context(), servers, sites, siteID, upstreamServersToL7Payload(0, remaining)); err != nil {
						writeError(w, http.StatusBadGateway, err.Error())
						return
					}
					if err := upstreamServers.Delete(r.Context(), siteID, upstreamID); err != nil {
						writeError(w, http.StatusInternalServerError, "failed to delete upstream server")
						return
					}
					w.WriteHeader(http.StatusNoContent)
				default:
					writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				}
				return
			}
		}

		id, ok := parseID(r.URL.Path, "/sites/")
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}

		switch r.Method {
		case http.MethodGet:
			item, err := sites.Get(r.Context(), id)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "site not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to load site")
				return
			}
			writeJSON(w, http.StatusOK, item)
		case http.MethodPut, http.MethodPatch:
			var payload store.SiteInput
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			payload = payload.Normalize()
			if payload.Domain == "" {
				writeError(w, http.StatusBadRequest, "domain is required")
				return
			}
			if _, err := sites.Update(r.Context(), id, payload); err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "site not found")
					return
				}
				if store.IsDuplicateDomain(err) {
					writeError(w, http.StatusConflict, "domain already exists")
					return
				}
				if strings.Contains(err.Error(), "invalid certificate expiry") {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to update site")
				return
			}
			if err := sites.UpdateSiteServers(r.Context(), id, payload.ServerIDs); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to assign servers")
				return
			}
			updated, err := sites.Get(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load updated site")
				return
			}
			writeJSON(w, http.StatusOK, updated)
		case http.MethodDelete:
			if err := sites.Delete(r.Context(), id); err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "site not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to delete site")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func loadSitePortsConfig(
	ctx context.Context,
	sites store.SiteStore,
	servers store.ServerStore,
	siteListeningPorts store.SiteListeningPortStore,
	siteID int64,
) (store.SitePortsConfig, error) {
	site, err := sites.Get(ctx, siteID)
	if err != nil {
		return store.SitePortsConfig{}, err
	}
	edges := make([]store.SiteEdgeServer, 0, len(site.ServerIDs))
	for _, serverID := range site.ServerIDs {
		view, err := servers.GetView(ctx, serverID)
		if err != nil {
			if store.IsNotFound(err) {
				continue
			}
			return store.SitePortsConfig{}, err
		}
		edges = append(edges, store.SiteEdgeServer{
			ID:   view.ID,
			Name: view.Name,
			IP:   view.IP,
		})
	}
	return siteListeningPorts.BuildConfig(ctx, siteID, edges)
}

func validateSitePortSelections(
	ctx context.Context,
	siteListeningPorts store.SiteListeningPortStore,
	serverID int64,
	httpPortIDs, httpsPortIDs []int64,
) ([]int64, string) {
	ports, err := siteListeningPorts.ListPortsForServer(ctx, serverID)
	if err != nil {
		return nil, "failed to load listening ports for server"
	}
	byID := make(map[int64]store.ListeningPort, len(ports))
	for _, port := range ports {
		byID[port.ID] = port
	}

	merged := make([]int64, 0, len(httpPortIDs)+len(httpsPortIDs))
	seen := make(map[int64]struct{}, len(httpPortIDs)+len(httpsPortIDs))

	appendValidated := func(ids []int64, wantProtocol string) string {
		for _, id := range ids {
			if id <= 0 {
				return "invalid listening port id"
			}
			port, ok := byID[id]
			if !ok {
				return "listening port does not belong to the selected server"
			}
			protocol := strings.ToUpper(strings.TrimSpace(port.Protocol))
			if protocol == "" {
				protocol = "HTTP"
			}
			if protocol != wantProtocol {
				return fmt.Sprintf("port %d is not %s", port.Port, wantProtocol)
			}
			if _, exists := seen[id]; exists {
				continue
			}
			seen[id] = struct{}{}
			merged = append(merged, id)
		}
		return ""
	}

	if msg := appendValidated(httpPortIDs, "HTTP"); msg != "" {
		return nil, msg
	}
	if msg := appendValidated(httpsPortIDs, "HTTPS"); msg != "" {
		return nil, msg
	}
	return merged, ""
}
