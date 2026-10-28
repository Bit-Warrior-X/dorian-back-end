package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"vue-project-backend/internal/store"
)

// predefinedWafEdge holds stores needed to push /waf-rules mutations to edges
// that host sites assigned to the rule set.
type predefinedWafEdge struct {
	servers store.ServerStore
	sites   store.SiteStore
	l7      siteL7Stores
}

func writePredefinedWafRuleError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if store.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "waf rule not found")
		return true
	}
	writeError(w, http.StatusInternalServerError, "failed to load waf rule")
	return true
}

func writePredefinedWafSyncError(w http.ResponseWriter, err error, message string) bool {
	if err == nil {
		return false
	}
	writeError(w, http.StatusBadGateway, message)
	return true
}

func (edge predefinedWafEdge) syncSites(ctx context.Context, wafRuleID int64, syncOne func(context.Context, int64) error) error {
	if edge.sites == nil || syncOne == nil {
		return nil
	}
	return syncWafRuleToAssignedSites(ctx, edge.sites, wafRuleID, syncOne)
}

func handlePredefinedWafWhitelist(w http.ResponseWriter, r *http.Request, wafRules store.WafRuleStore, wafWhitelist store.WafWhitelistStore, edge predefinedWafEdge) {
	wafRuleID, ruleID, isBatch, ok := parseWafRuleResourcePath(r.URL.Path, "whitelist")
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if writePredefinedWafRuleError(w, requireWafRuleExists(r.Context(), wafRules, wafRuleID)) {
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
			if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
				return callL7UpdateWhitelist(ctx, edge.servers, edge.sites, siteID, wafWhitelist)
			}), "failed to sync waf whitelist rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateWhitelist(ctx, edge.servers, edge.sites, siteID, wafWhitelist)
		}), "failed to sync waf whitelist rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateWhitelist(ctx, edge.servers, edge.sites, siteID, wafWhitelist)
		}), "failed to sync waf whitelist rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateWhitelist(ctx, edge.servers, edge.sites, siteID, wafWhitelist)
		}), "failed to sync waf whitelist rules") {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handlePredefinedWafBlacklist(w http.ResponseWriter, r *http.Request, wafRules store.WafRuleStore, wafBlacklist store.WafBlacklistStore, edge predefinedWafEdge) {
	wafRuleID, ruleID, isBatch, ok := parseWafRuleResourcePath(r.URL.Path, "blacklist")
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if writePredefinedWafRuleError(w, requireWafRuleExists(r.Context(), wafRules, wafRuleID)) {
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
			if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
				return callL7UpdateBlacklist(ctx, edge.servers, edge.sites, siteID, wafBlacklist)
			}), "failed to sync waf blacklist rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateBlacklist(ctx, edge.servers, edge.sites, siteID, wafBlacklist)
		}), "failed to sync waf blacklist rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateBlacklist(ctx, edge.servers, edge.sites, siteID, wafBlacklist)
		}), "failed to sync waf blacklist rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateBlacklist(ctx, edge.servers, edge.sites, siteID, wafBlacklist)
		}), "failed to sync waf blacklist rules") {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handlePredefinedWafGeo(w http.ResponseWriter, r *http.Request, wafRules store.WafRuleStore, wafGeo store.WafGeoStore, edge predefinedWafEdge) {
	wafRuleID, ruleID, isBatch, ok := parseWafRuleResourcePath(r.URL.Path, "geolocation")
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if writePredefinedWafRuleError(w, requireWafRuleExists(r.Context(), wafRules, wafRuleID)) {
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
			if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
				return callL7UpdateGeo(ctx, edge.servers, edge.sites, siteID, wafGeo)
			}), "failed to sync waf geolocation rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateGeo(ctx, edge.servers, edge.sites, siteID, wafGeo)
		}), "failed to sync waf geolocation rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateGeo(ctx, edge.servers, edge.sites, siteID, wafGeo)
		}), "failed to sync waf geolocation rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateGeo(ctx, edge.servers, edge.sites, siteID, wafGeo)
		}), "failed to sync waf geolocation rules") {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handlePredefinedWafAntiCc(w http.ResponseWriter, r *http.Request, wafRules store.WafRuleStore, wafAntiCc store.WafAntiCcStore, edge predefinedWafEdge) {
	wafRuleID, ruleID, isBatch, ok := parseWafRuleResourcePath(r.URL.Path, "anti-cc")
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if writePredefinedWafRuleError(w, requireWafRuleExists(r.Context(), wafRules, wafRuleID)) {
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
			if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
				_, err := callL7UpdateSite(ctx, edge.servers, edge.sites, siteID, edge.l7)
				return err
			}), "failed to sync waf anti-cc rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			_, err := callL7UpdateSite(ctx, edge.servers, edge.sites, siteID, edge.l7)
			return err
		}), "failed to sync waf anti-cc rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			_, err := callL7UpdateSite(ctx, edge.servers, edge.sites, siteID, edge.l7)
			return err
		}), "failed to sync waf anti-cc rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			_, err := callL7UpdateSite(ctx, edge.servers, edge.sites, siteID, edge.l7)
			return err
		}), "failed to sync waf anti-cc rules") {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handlePredefinedWafAntiHeader(w http.ResponseWriter, r *http.Request, wafRules store.WafRuleStore, wafAntiHeader store.WafAntiHeaderStore, edge predefinedWafEdge) {
	wafRuleID, ruleID, isBatch, ok := parseWafRuleResourcePath(r.URL.Path, "anti-header")
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if writePredefinedWafRuleError(w, requireWafRuleExists(r.Context(), wafRules, wafRuleID)) {
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
			if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
				return callL7UpdateAntiHeader(ctx, edge.servers, edge.sites, siteID, wafAntiHeader)
			}), "failed to sync waf anti-header rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateAntiHeader(ctx, edge.servers, edge.sites, siteID, wafAntiHeader)
		}), "failed to sync waf anti-header rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateAntiHeader(ctx, edge.servers, edge.sites, siteID, wafAntiHeader)
		}), "failed to sync waf anti-header rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateAntiHeader(ctx, edge.servers, edge.sites, siteID, wafAntiHeader)
		}), "failed to sync waf anti-header rules") {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handlePredefinedWafInterval(w http.ResponseWriter, r *http.Request, wafRules store.WafRuleStore, wafInterval store.WafIntervalStore, edge predefinedWafEdge) {
	wafRuleID, ruleID, isBatch, ok := parseWafRuleResourcePath(r.URL.Path, "interval-freq-limit")
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if writePredefinedWafRuleError(w, requireWafRuleExists(r.Context(), wafRules, wafRuleID)) {
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
			if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
				return callL7UpdateIntervalFreqLimit(ctx, edge.servers, edge.sites, siteID, wafInterval)
			}), "failed to sync waf interval frequency rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateIntervalFreqLimit(ctx, edge.servers, edge.sites, siteID, wafInterval)
		}), "failed to sync waf interval frequency rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateIntervalFreqLimit(ctx, edge.servers, edge.sites, siteID, wafInterval)
		}), "failed to sync waf interval frequency rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateIntervalFreqLimit(ctx, edge.servers, edge.sites, siteID, wafInterval)
		}), "failed to sync waf interval frequency rules") {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handlePredefinedWafSecond(w http.ResponseWriter, r *http.Request, wafRules store.WafRuleStore, wafSecond store.WafSecondStore, edge predefinedWafEdge) {
	wafRuleID, ruleID, isBatch, ok := parseWafRuleResourcePath(r.URL.Path, "second-freq-limit")
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if writePredefinedWafRuleError(w, requireWafRuleExists(r.Context(), wafRules, wafRuleID)) {
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
			if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
				return callL7UpdateSecondFreqLimit(ctx, edge.servers, edge.sites, siteID, wafSecond)
			}), "failed to sync waf second frequency rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateSecondFreqLimit(ctx, edge.servers, edge.sites, siteID, wafSecond)
		}), "failed to sync waf second frequency rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateSecondFreqLimit(ctx, edge.servers, edge.sites, siteID, wafSecond)
		}), "failed to sync waf second frequency rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateSecondFreqLimit(ctx, edge.servers, edge.sites, siteID, wafSecond)
		}), "failed to sync waf second frequency rules") {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handlePredefinedWafResponse(w http.ResponseWriter, r *http.Request, wafRules store.WafRuleStore, wafResponse store.WafResponseStore, edge predefinedWafEdge) {
	wafRuleID, ruleID, isBatch, ok := parseWafRuleResourcePath(r.URL.Path, "response-freq")
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if writePredefinedWafRuleError(w, requireWafRuleExists(r.Context(), wafRules, wafRuleID)) {
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
			if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
				return callL7UpdateResponseFreq(ctx, edge.servers, edge.sites, siteID, wafResponse)
			}), "failed to sync waf response frequency rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateResponseFreq(ctx, edge.servers, edge.sites, siteID, wafResponse)
		}), "failed to sync waf response frequency rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateResponseFreq(ctx, edge.servers, edge.sites, siteID, wafResponse)
		}), "failed to sync waf response frequency rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateResponseFreq(ctx, edge.servers, edge.sites, siteID, wafResponse)
		}), "failed to sync waf response frequency rules") {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handlePredefinedWafUserAgent(w http.ResponseWriter, r *http.Request, wafRules store.WafRuleStore, wafUserAgent store.WafUserAgentStore, edge predefinedWafEdge) {
	wafRuleID, ruleID, isBatch, ok := parseWafRuleResourcePath(r.URL.Path, "user-agent")
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if writePredefinedWafRuleError(w, requireWafRuleExists(r.Context(), wafRules, wafRuleID)) {
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
			if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
				return callL7UpdateUserAgent(ctx, edge.servers, edge.sites, siteID, wafUserAgent)
			}), "failed to sync waf user-agent rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateUserAgent(ctx, edge.servers, edge.sites, siteID, wafUserAgent)
		}), "failed to sync waf user-agent rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateUserAgent(ctx, edge.servers, edge.sites, siteID, wafUserAgent)
		}), "failed to sync waf user-agent rules") {
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
		if writePredefinedWafSyncError(w, edge.syncSites(r.Context(), wafRuleID, func(ctx context.Context, siteID int64) error {
			return callL7UpdateUserAgent(ctx, edge.servers, edge.sites, siteID, wafUserAgent)
		}), "failed to sync waf user-agent rules") {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
