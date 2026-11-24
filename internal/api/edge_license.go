package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

// Edge license HTTP API (Angelos). See PANEL_EDGE_LICENSE_INTEGRATION.md.
const (
	edgeLicenseDeployPath = "/API/license/deploy"
	edgeLicenseSitesPath  = "/API/license/sites"
)

type edgeLicenseDeployRequest struct {
	Token                 string            `json:"token"`
	Format                string            `json:"format,omitempty"`
	Edge                  string            `json:"edge,omitempty"`
	Components            map[string]string `json:"components,omitempty"`
	BridgeLicense         string            `json:"bridge_license,omitempty"`
	BridgeLicenseEncoding string            `json:"bridge_license_encoding,omitempty"`
	// Legacy classic-only fields (migration).
	License         string `json:"license,omitempty"`
	LicenseEncoding string `json:"license_encoding,omitempty"`
}

type edgeLicenseDeployResponse struct {
	LicenseType   string `json:"license_type"`
	LicenseState  string `json:"license_state"`
	AllowsL4      bool   `json:"allows_l4"`
	AllowsL7      bool   `json:"allows_l7"`
	ConfigLocked  bool   `json:"config_locked"`
	Description   string `json:"description"`
	Message       string `json:"message"`
	Error         string `json:"error"`
}

type edgeSiteLicenseInstallRequest struct {
	Token   string `json:"token"`
	SiteID  int64  `json:"site_id"`
	Format  string `json:"format,omitempty"`
	License string `json:"license"` // signed dorian.v2 site token (or legacy JSON during migration)
}

type mintSiteEntitlementResponse struct {
	Format      string `json:"format"`
	SiteID      int64  `json:"site_id"`
	LicenseKind string `json:"license_kind"`
	MachineID   string `json:"machine_id"`
	ExpUnix     int64  `json:"exp_unix"`
	License     string `json:"license"`
}

type edgeLicenseHTTPError struct {
	Status int
	Body   string
	Path   string
}

func (e *edgeLicenseHTTPError) Error() string {
	if e == nil {
		return "edge license request failed"
	}
	msg := summarizeEdgeLicenseStatus(e.Status, e.Body)
	if msg != "" {
		return fmt.Sprintf("%s: %s", e.Path, msg)
	}
	body := strings.TrimSpace(e.Body)
	if body == "" || looksLikeHTML(body) {
		return fmt.Sprintf("%s returned status %d", e.Path, e.Status)
	}
	return fmt.Sprintf("%s returned status %d: %s", e.Path, e.Status, body)
}

func summarizeEdgeLicenseStatus(status int, body string) string {
	trimmed := strings.TrimSpace(body)
	switch status {
	case http.StatusLocked: // 423
		return "license config locked on edge (expired/frozen); renew before changing config"
	case http.StatusForbidden: // 403
		return "edge product type does not allow this layer"
	case http.StatusPaymentRequired: // 402
		return "site is not entitled on this edge (missing or invalid sites/<id>.dlic)"
	case http.StatusBadRequest: // 400
		if trimmed != "" && !looksLikeHTML(trimmed) {
			return "bad entitlement request: " + truncateForLog(trimmed, 240)
		}
		return "bad or unsigned entitlement token"
	}
	return ""
}

func truncateForLog(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func formatL7StatusForOperator(err error) string {
	var statusErr *l7StatusError
	if errorsAsL7(err, &statusErr) {
		if msg := summarizeEdgeLicenseStatus(statusErr.Status, statusErr.Body); msg != "" {
			return msg
		}
	}
	var edgeErr *edgeLicenseHTTPError
	if errorsAsEdgeLicense(err, &edgeErr) {
		return edgeErr.Error()
	}
	return err.Error()
}

func errorsAsL7(err error, target **l7StatusError) bool {
	if err == nil || target == nil {
		return false
	}
	if e, ok := err.(*l7StatusError); ok {
		*target = e
		return true
	}
	return false
}

func errorsAsEdgeLicense(err error, target **edgeLicenseHTTPError) bool {
	if err == nil || target == nil {
		return false
	}
	if e, ok := err.(*edgeLicenseHTTPError); ok {
		*target = e
		return true
	}
	return false
}

// edgeLicenseAPIUnsupported is true when the edge agent has no /API/license/*
// routes yet (older Angelos). Callers should fail-open for site entitlements.
func edgeLicenseAPIUnsupported(err error) bool {
	var edgeErr *edgeLicenseHTTPError
	if !errorsAsEdgeLicense(err, &edgeErr) || edgeErr == nil {
		return false
	}
	return edgeErr.Status == http.StatusNotFound
}

// durationDaysUntil returns whole days from now until end (ceil), at least 1.
// Used so classic license.lic expiry matches panel current_period_end (no +14 grace baked in).
func durationDaysUntil(end, now time.Time) int {
	if end.IsZero() {
		return 1
	}
	hours := end.UTC().Sub(now.UTC()).Hours()
	days := int(math.Ceil(hours / 24))
	if days < 1 {
		return 1
	}
	if days > 3650 {
		return 3650
	}
	return days
}

func deployEdgeLicenseRequest(ctx context.Context, server store.ServerView, payload edgeLicenseDeployRequest) (edgeLicenseDeployResponse, error) {
	if strings.TrimSpace(server.IP) == "" || strings.TrimSpace(server.Token) == "" {
		return edgeLicenseDeployResponse{}, fmt.Errorf("server missing ip or token")
	}
	payload.Token = strings.TrimSpace(server.Token)
	body, err := json.Marshal(payload)
	if err != nil {
		return edgeLicenseDeployResponse{}, err
	}
	req, err := newL7EdgeRequest(ctx, server, edgeLicenseDeployPath, body)
	if err != nil {
		return edgeLicenseDeployResponse{}, err
	}
	resp, err := l7EdgeClient.Do(req)
	if err != nil {
		return edgeLicenseDeployResponse{}, fmt.Errorf("license deploy request failed: %w", err)
	}
	defer resp.Body.Close()
	limited, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return edgeLicenseDeployResponse{}, &edgeLicenseHTTPError{
			Status: resp.StatusCode,
			Body:   string(limited),
			Path:   edgeLicenseDeployPath,
		}
	}
	var decoded edgeLicenseDeployResponse
	if len(bytes.TrimSpace(limited)) > 0 {
		_ = json.Unmarshal(limited, &decoded)
	}
	return decoded, nil
}

// deployEdgeLicense posts a classic-only bridge (migration / fallback).
func deployEdgeLicense(ctx context.Context, server store.ServerView, licenseBody string) (edgeLicenseDeployResponse, error) {
	licenseBody = strings.TrimSpace(licenseBody)
	if licenseBody == "" {
		return edgeLicenseDeployResponse{}, fmt.Errorf("empty license body")
	}
	return deployEdgeLicenseRequest(ctx, server, edgeLicenseDeployRequest{
		License:         licenseBody,
		LicenseEncoding: "plain",
	})
}

func installEdgeSiteLicense(ctx context.Context, server store.ServerView, siteID int64, kind string, state string, expiresAt time.Time, machineID string) error {
	if siteID <= 0 {
		return fmt.Errorf("invalid site id")
	}
	if strings.TrimSpace(server.IP) == "" || strings.TrimSpace(server.Token) == "" {
		return fmt.Errorf("server missing ip or token")
	}
	kind = strings.TrimSpace(kind)
	if kind == "" {
		kind = store.LicenseKindSiteOwn
	}
	state = strings.TrimSpace(state)
	if state == "" {
		state = store.LicenseStatusActive
	}

	// Prefer signed dorian.v2 site token (PANEL_EDGE_LICENSE_INTEGRATION §3.3).
	if token, mintErr := mintSiteEntitlement(ctx, server, siteID, kind, expiresAt); mintErr != nil {
		log.Printf("[api] edge site license server=%d site=%d: mint_site_entitlement failed (%v); falling back to classic JSON",
			server.ID, siteID, mintErr)
	} else {
		v2Err := postEdgeSiteLicense(ctx, server, edgeSiteLicenseInstallRequest{
			Token:   strings.TrimSpace(server.Token),
			SiteID:  siteID,
			Format:  "dorian.v2",
			License: token,
		})
		if v2Err == nil {
			return nil
		}
		if edgeLicenseAPIUnsupported(v2Err) {
			return v2Err
		}
		if !isEdgeLicenseBadRequest(v2Err) {
			return v2Err
		}
		log.Printf("[api] edge site license server=%d site=%d: dorian.v2 rejected (%v); falling back to classic JSON",
			server.ID, siteID, v2Err)
	}

	// Older Angelos (pre-dorian.v2) expects an unsigned license object → sites/<id>.lic.
	classic := map[string]any{
		"token":   strings.TrimSpace(server.Token),
		"site_id": siteID,
		"license": map[string]any{
			"site_id":      siteID,
			"license_kind": kind,
			"state":        state,
			"expires_at":   expiresAt.UTC().Format(time.RFC3339),
			"machine_id":   strings.TrimSpace(machineID),
		},
	}
	body, err := json.Marshal(classic)
	if err != nil {
		return err
	}
	req, err := newL7EdgeRequest(ctx, server, edgeLicenseSitesPath, body)
	if err != nil {
		return err
	}
	resp, err := l7EdgeClient.Do(req)
	if err != nil {
		return fmt.Errorf("site license install failed: %w", err)
	}
	defer resp.Body.Close()
	limited, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return &edgeLicenseHTTPError{
			Status: resp.StatusCode,
			Body:   string(limited),
			Path:   edgeLicenseSitesPath,
		}
	}
	return nil
}

func postEdgeSiteLicense(ctx context.Context, server store.ServerView, payload edgeSiteLicenseInstallRequest) error {
	payload.Token = strings.TrimSpace(server.Token)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := newL7EdgeRequest(ctx, server, edgeLicenseSitesPath, body)
	if err != nil {
		return err
	}
	resp, err := l7EdgeClient.Do(req)
	if err != nil {
		return fmt.Errorf("site license install failed: %w", err)
	}
	defer resp.Body.Close()
	limited, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return &edgeLicenseHTTPError{
			Status: resp.StatusCode,
			Body:   string(limited),
			Path:   edgeLicenseSitesPath,
		}
	}
	return nil
}

func deleteEdgeSiteLicense(ctx context.Context, server store.ServerView, siteID int64) error {
	if siteID <= 0 {
		return fmt.Errorf("invalid site id")
	}
	if strings.TrimSpace(server.IP) == "" || strings.TrimSpace(server.Token) == "" {
		return fmt.Errorf("server missing ip or token")
	}
	path := edgeLicenseSitesPath + "/" + strconv.FormatInt(siteID, 10)
	body, err := json.Marshal(map[string]string{"token": strings.TrimSpace(server.Token)})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, l7EdgeURL(server.IP, path), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	signEdgeRequest(req, server.Token, body, time.Now())
	resp, err := l7EdgeClient.Do(req)
	if err != nil {
		return fmt.Errorf("site license delete failed: %w", err)
	}
	defer resp.Body.Close()
	limited, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// 404 = already gone / older Angelos without site licenses — treat as ok for cleanup.
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return &edgeLicenseHTTPError{
			Status: resp.StatusCode,
			Body:   string(limited),
			Path:   path,
		}
	}
	return nil
}

// pushLicenseBundleToEdge prefers dorian.v2 deploy (§3.1), falling back to classic-only.
func pushLicenseBundleToEdge(ctx context.Context, server store.ServerView, deployResp deployCreateServerResponse) error {
	bridge := strings.TrimSpace(deployResp.BridgeLicense)
	if bridge == "" {
		bridge = strings.TrimSpace(deployResp.License)
	}
	if strings.EqualFold(strings.TrimSpace(deployResp.Format), "dorian.v2") &&
		strings.TrimSpace(deployResp.Edge) != "" && len(deployResp.Components) > 0 {
		// Include classic `license` alongside v2 so pre-v2 Angelos (Missing 'license')
		// and v2 Angelos (format=dorian.v2) both accept the same payload.
		result, err := deployEdgeLicenseRequest(ctx, server, edgeLicenseDeployRequest{
			Format:                "dorian.v2",
			Edge:                  strings.TrimSpace(deployResp.Edge),
			Components:            deployResp.Components,
			BridgeLicense:         bridge,
			BridgeLicenseEncoding: firstNonEmpty(strings.TrimSpace(deployResp.BridgeLicenseEncoding), "plain"),
			License:               bridge,
			LicenseEncoding:       "plain",
		})
		if err != nil {
			// Older Angelos may not accept format=dorian.v2 yet — try classic bridge.
			if edgeLicenseAPIUnsupported(err) || isEdgeLicenseBadRequest(err) {
				log.Printf("[api] edge license deploy server=%d: dorian.v2 rejected (%v); falling back to classic bridge", server.ID, err)
				if bridge == "" {
					return err
				}
				result, err = deployEdgeLicense(ctx, server, bridge)
				if err != nil {
					return err
				}
				log.Printf("[api] edge license deploy server=%d classic type=%q state=%q allows_l4=%v allows_l7=%v locked=%v",
					server.ID, result.LicenseType, result.LicenseState, result.AllowsL4, result.AllowsL7, result.ConfigLocked)
				return nil
			}
			return err
		}
		log.Printf("[api] edge license deploy server=%d dorian.v2 type=%q state=%q allows_l4=%v allows_l7=%v locked=%v",
			server.ID, result.LicenseType, result.LicenseState, result.AllowsL4, result.AllowsL7, result.ConfigLocked)
		return nil
	}
	if bridge == "" {
		return nil
	}
	result, err := deployEdgeLicense(ctx, server, bridge)
	if err != nil {
		return err
	}
	log.Printf("[api] edge license deploy server=%d classic type=%q state=%q allows_l4=%v allows_l7=%v locked=%v",
		server.ID, result.LicenseType, result.LicenseState, result.AllowsL4, result.AllowsL7, result.ConfigLocked)
	return nil
}

func isEdgeLicenseBadRequest(err error) bool {
	var edgeErr *edgeLicenseHTTPError
	return errorsAsEdgeLicense(err, &edgeErr) && edgeErr != nil && edgeErr.Status == http.StatusBadRequest
}

// mintSiteEntitlement asks deploy_license to sign a dorian.v2 site token with the
// same RSA key that signed this edge's classic bridge.
func mintSiteEntitlement(ctx context.Context, server store.ServerView, siteID int64, kind string, expiresAt time.Time) (string, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(panelDeployLicenseBaseURL), "/")
	if baseURL == "" {
		return "", fmt.Errorf("deploy license base url is not configured")
	}
	expUnix := expiresAt.UTC().Unix()
	if expiresAt.IsZero() {
		expUnix = time.Now().UTC().AddDate(0, 0, 30).Unix()
	}
	body, err := json.Marshal(map[string]any{
		"token":        strings.TrimSpace(server.Token),
		"site_id":      siteID,
		"license_kind": kind,
		"exp_unix":     expUnix,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/mint_site_entitlement", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("mint_site_entitlement request failed: %w", err)
	}
	defer resp.Body.Close()
	limited, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("mint_site_entitlement status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	var decoded mintSiteEntitlementResponse
	if err := json.Unmarshal(limited, &decoded); err != nil {
		return "", fmt.Errorf("decode mint_site_entitlement: %w", err)
	}
	token := strings.TrimSpace(decoded.License)
	if token == "" || !strings.HasPrefix(token, "dorian.v2.") {
		return "", fmt.Errorf("mint_site_entitlement returned empty or non-v2 token")
	}
	return token, nil
}

// panelOrderStore is set by NewRouter so site L7 pushes can install sites/<id>.dlic
// before config (PANEL_EDGE_LICENSE_INTEGRATION §3.3 / §4).
var panelOrderStore store.OrderStore

// panelDeployLicenseBaseURL is set by NewRouter for mint_site_entitlement.
var panelDeployLicenseBaseURL string

func lookupInstallableSiteLicense(ctx context.Context, siteID int64) (store.License, bool) {
	if panelOrderStore == nil || siteID <= 0 {
		return store.License{}, false
	}
	license, err := panelOrderStore.LicenseFor(ctx, store.LicenseScopeSite, siteID)
	if err != nil {
		return store.License{}, false
	}
	switch license.Status {
	case store.LicenseStatusActive, store.LicenseStatusPastDue:
		return license, true
	default:
		return store.License{}, false
	}
}

// siteLicenseAssignBlock explains why a site cannot be placed on an edge yet.
func siteLicenseAssignBlock(ctx context.Context, siteID int64) string {
	if panelOrderStore == nil || siteID <= 0 {
		return ""
	}
	license, err := panelOrderStore.LicenseFor(ctx, store.LicenseScopeSite, siteID)
	if err != nil {
		if store.IsNotFound(err) {
			return "this site has no license yet — order site protection (or finish the site order) before assigning edges"
		}
		return ""
	}
	switch license.Status {
	case store.LicenseStatusCancelled:
		return "this site's license is cancelled — place a new site order to protect it again, then assign the edge"
	case store.LicenseStatusExpired:
		return "this site's license is expired — renew it before assigning edges"
	default:
		return ""
	}
}

func siteLicenseFileState(status string) string {
	if status == store.LicenseStatusPastDue {
		return store.LicenseStatusPastDue
	}
	return store.LicenseStatusActive
}

// installSiteLicenseOnAssignedEdges writes sites/<id>.dlic on every edge that hosts the site.
func installSiteLicenseOnAssignedEdges(
	ctx context.Context,
	servers store.ServerStore,
	sites store.SiteStore,
	siteID int64,
	kind string,
	state string,
	expiresAt time.Time,
) []string {
	warnings := make([]string, 0)
	edgeIDs, err := siteEdgeServerIDs(ctx, sites, siteID)
	if err != nil {
		return []string{err.Error()}
	}
	for _, edgeID := range edgeIDs {
		server, err := servers.GetView(ctx, edgeID)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("edge #%d: %v", edgeID, err))
			continue
		}
		if err := installEdgeSiteLicense(ctx, server, siteID, kind, state, expiresAt, ""); err != nil {
			// Older Angelos without /API/license/sites fail-opens — do not surface as a setup warning.
			if edgeLicenseAPIUnsupported(err) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf("%s: %v", edgeLabel(server.Name, server.ID), formatL7StatusForOperator(err)))
		}
	}
	return warnings
}

// deleteSiteLicenseOnEdges removes sites/<id>.dlic from specific edges (e.g. after unassign).
func deleteSiteLicenseOnEdges(ctx context.Context, servers store.ServerStore, edgeIDs []int64, siteID int64) []string {
	warnings := make([]string, 0)
	for _, edgeID := range edgeIDs {
		if edgeID <= 0 {
			continue
		}
		server, err := servers.GetView(ctx, edgeID)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("edge #%d: %v", edgeID, err))
			continue
		}
		if err := deleteEdgeSiteLicense(ctx, server, siteID); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", edgeLabel(server.Name, server.ID), formatL7StatusForOperator(err)))
		}
	}
	return warnings
}

func removedServerIDs(before, after []int64) []int64 {
	keep := make(map[int64]bool, len(after))
	for _, id := range after {
		keep[id] = true
	}
	out := make([]int64, 0)
	for _, id := range before {
		if id > 0 && !keep[id] {
			out = append(out, id)
		}
	}
	return out
}

func deleteSiteLicenseOnAssignedEdges(ctx context.Context, servers store.ServerStore, sites store.SiteStore, siteID int64) []string {
	warnings := make([]string, 0)
	edgeIDs, err := siteEdgeServerIDs(ctx, sites, siteID)
	if err != nil {
		return []string{err.Error()}
	}
	for _, edgeID := range edgeIDs {
		server, err := servers.GetView(ctx, edgeID)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("edge #%d: %v", edgeID, err))
			continue
		}
		if err := deleteEdgeSiteLicense(ctx, server, siteID); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", edgeLabel(server.Name, server.ID), err))
		}
	}
	return warnings
}
