package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"vue-project-backend/internal/store"
)

func parseWafRuleResourcePath(path, resource string) (wafRuleID int64, ruleID int64, isBatch bool, ok bool) {
	trimmed := strings.TrimPrefix(path, "/waf-rules/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return 0, 0, false, false
	}
	if parts[1] != "waf" || parts[2] != resource {
		return 0, 0, false, false
	}
	wafRuleID, ok = parsePositiveInt(parts[0])
	if !ok {
		return 0, 0, false, false
	}
	if len(parts) == 3 {
		return wafRuleID, 0, false, true
	}
	if len(parts) == 4 && parts[3] == "batch-delete" {
		return wafRuleID, 0, true, true
	}
	if len(parts) == 4 {
		ruleID, ok = parsePositiveInt(parts[3])
		if !ok {
			return 0, 0, false, false
		}
		return wafRuleID, ruleID, false, true
	}
	return 0, 0, false, false
}

func requireWafRuleExists(ctx context.Context, wafRules store.WafRuleStore, wafRuleID int64) error {
	_, err := wafRules.Get(ctx, wafRuleID)
	return err
}

func wafRulesHandler(wafRules store.WafRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			role := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("role")))
			var (
				list []store.WafRule
				err  error
			)
			if role != "" {
				list, err = wafRules.ListByRole(r.Context(), role)
			} else {
				list, err = wafRules.List(r.Context())
			}
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load waf rules")
				return
			}
			writeJSON(w, http.StatusOK, list)
		case http.MethodPost:
			var payload store.WafRuleInput
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			payload.Role = "predefined"
			created, err := wafRules.Create(r.Context(), store.WafRuleInput{
				Name: payload.Name,
				Role: "predefined",
			})
			if err != nil {
				if strings.Contains(err.Error(), "name is required") {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to create waf rule")
				return
			}
			writeJSON(w, http.StatusCreated, created)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func wafRuleDetailHandler(
	wafRules store.WafRuleStore,
	wafWhitelist store.WafWhitelistStore,
	wafBlacklist store.WafBlacklistStore,
	wafGeo store.WafGeoStore,
	wafAntiCc store.WafAntiCcStore,
	wafAntiHeader store.WafAntiHeaderStore,
	wafInterval store.WafIntervalStore,
	wafSecond store.WafSecondStore,
	wafResponse store.WafResponseStore,
	wafUserAgent store.WafUserAgentStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if id, ok := parseIDWithSuffix(path, "/waf-rules/", "/duplicate"); ok {
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			var payload struct {
				Name string `json:"name"`
			}
			if r.Body != nil {
				_ = json.NewDecoder(r.Body).Decode(&payload)
			}
			duplicated, err := wafRules.Duplicate(r.Context(), id, payload.Name)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "waf rule not found")
					return
				}
				if strings.Contains(err.Error(), "only predefined") || strings.Contains(err.Error(), "name is required") {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to duplicate waf rule")
				return
			}
			writeJSON(w, http.StatusCreated, duplicated)
			return
		}
		if strings.Contains(path, "/waf/") {
			switch {
			case strings.Contains(path, "/waf/whitelist"):
				handlePredefinedWafWhitelist(w, r, wafRules, wafWhitelist)
			case strings.Contains(path, "/waf/blacklist"):
				handlePredefinedWafBlacklist(w, r, wafRules, wafBlacklist)
			case strings.Contains(path, "/waf/geolocation"):
				handlePredefinedWafGeo(w, r, wafRules, wafGeo)
			case strings.Contains(path, "/waf/anti-cc"):
				handlePredefinedWafAntiCc(w, r, wafRules, wafAntiCc)
			case strings.Contains(path, "/waf/anti-header"):
				handlePredefinedWafAntiHeader(w, r, wafRules, wafAntiHeader)
			case strings.Contains(path, "/waf/interval-freq-limit"):
				handlePredefinedWafInterval(w, r, wafRules, wafInterval)
			case strings.Contains(path, "/waf/second-freq-limit"):
				handlePredefinedWafSecond(w, r, wafRules, wafSecond)
			case strings.Contains(path, "/waf/response-freq"):
				handlePredefinedWafResponse(w, r, wafRules, wafResponse)
			case strings.Contains(path, "/waf/user-agent"):
				handlePredefinedWafUserAgent(w, r, wafRules, wafUserAgent)
			default:
				writeError(w, http.StatusNotFound, "not found")
			}
			return
		}

		id, ok := parseID(path, "/waf-rules/")
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}

		switch r.Method {
		case http.MethodGet:
			item, err := wafRules.Get(r.Context(), id)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "waf rule not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to load waf rule")
				return
			}
			writeJSON(w, http.StatusOK, item)
		case http.MethodPut, http.MethodPatch:
			existing, err := wafRules.Get(r.Context(), id)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "waf rule not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to load waf rule")
				return
			}
			var payload store.WafRuleInput
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			payload = payload.Normalize()
			role := payload.Role
			if role != "predefined" && role != "custom" {
				role = strings.ToLower(strings.TrimSpace(existing.Role))
				if role != "custom" {
					role = "predefined"
				}
			}
			updated, err := wafRules.Update(r.Context(), id, store.WafRuleInput{
				Name: payload.Name,
				Role: role,
			})
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "waf rule not found")
					return
				}
				if strings.Contains(err.Error(), "name is required") {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to update waf rule")
				return
			}
			writeJSON(w, http.StatusOK, updated)
		case http.MethodDelete:
			if err := wafRules.Delete(r.Context(), id); err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusNotFound, "waf rule not found")
					return
				}
				if strings.Contains(err.Error(), "assigned to one or more sites") {
					writeError(w, http.StatusConflict, err.Error())
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to delete waf rule")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}
