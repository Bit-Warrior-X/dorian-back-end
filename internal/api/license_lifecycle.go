package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

const (
	renewalLeadTime = 7 * 24 * time.Hour
	pastDueGrace    = 14 * 24 * time.Hour
)

// StartLicenseLifecycle runs the hourly renewal and expiry pass.
func (svc *orderService) StartLicenseLifecycle(ctx context.Context) {
	go func() {
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				svc.runLicenseLifecycle(ctx, time.Now().UTC())
				timer.Reset(time.Hour)
			}
		}
	}()
}

func (svc *orderService) runLicenseLifecycle(ctx context.Context, now time.Time) {
	licenses, err := svc.orders.ListLicenses(ctx, 0)
	if err != nil {
		log.Printf("[api] license lifecycle: list: %v", err)
		return
	}
	type renewalKey struct {
		userID int64
		period string
	}
	due := map[renewalKey][]int64{}
	for _, license := range licenses {
		if license.Status == store.LicenseStatusCancelled {
			continue
		}
		next := nextLicenseStatus(license, now)
		if next != license.Status {
			previous := license.Status
			license.Status = next
			if _, err := svc.orders.SaveLicense(ctx, license); err != nil {
				log.Printf("[api] license lifecycle: save license=%d: %v", license.ID, err)
				continue
			}
			svc.notifyLicenseStatus(ctx, license, previous)
			name := firstNonEmpty(license.TargetName, fmt.Sprintf("%s #%d", license.Scope, license.TargetID))
			switch next {
			case store.LicenseStatusCancelled:
				svc.recordLicenseEvent(ctx, license, store.LicenseEventCancelled,
					licenseEventTitle(store.LicenseEventCancelled, name),
					"Ended at period end.")
			case store.LicenseStatusExpired:
				svc.recordLicenseEvent(ctx, license, store.LicenseEventCancelled,
					"License expired: "+name,
					"Grace period ended.")
			case store.LicenseStatusPastDue:
				svc.recordLicenseEvent(ctx, license, "past_due",
					"License past due: "+name,
					fmt.Sprintf("Renew before %s to avoid lock.", license.CurrentPeriodEnd.Add(pastDueGrace).Format("2 Jan 2006")))
			}
			// After grace / cancel: remove site entitlement and L7 traffic config.
			if license.Scope == store.LicenseScopeSite &&
				(next == store.LicenseStatusExpired || next == store.LicenseStatusCancelled) {
				if err := svc.removeSiteTrafficAfterLicenseEnd(ctx, license.TargetID); err != nil {
					log.Printf("[api] license lifecycle: site %d traffic cleanup: %v", license.TargetID, err)
				}
			}
		}
		if license.CancelAtEnd || license.Status == store.LicenseStatusCancelled {
			continue
		}
		if license.UserID > 0 && license.RenewalOrderID == nil && license.Status != store.LicenseStatusExpired &&
			license.CurrentPeriodEnd.Sub(now) <= renewalLeadTime {
			key := renewalKey{userID: license.UserID, period: license.Period}
			due[key] = append(due[key], license.ID)
		}
	}
	for key, ids := range due {
		order, err := svc.createRenewalOrder(ctx, key.userID, 0, ids, key.period)
		if err != nil {
			log.Printf("[api] license lifecycle: renewal order user=%d: %v", key.userID, err)
			continue
		}
		log.Printf("[api] license lifecycle: renewal order=%d user=%d licenses=%d total=%.2f", order.ID, key.userID, len(ids), order.Total)
	}
}

// nextLicenseStatus: active until the period ends, past_due for 14 days, then expired.
// A license scheduled for cancellation becomes cancelled at the period end instead.
func nextLicenseStatus(license store.License, now time.Time) string {
	switch {
	case license.Status == store.LicenseStatusCancelled:
		return license.Status
	case now.Before(license.CurrentPeriodEnd):
		return store.LicenseStatusActive
	case license.CancelAtEnd:
		return store.LicenseStatusCancelled
	case now.Before(license.CurrentPeriodEnd.Add(pastDueGrace)):
		return store.LicenseStatusPastDue
	default:
		return store.LicenseStatusExpired
	}
}

func (svc *orderService) notifyLicenseStatus(ctx context.Context, license store.License, previous string) {
	if svc.notifications == nil || license.UserID <= 0 {
		return
	}
	name := firstNonEmpty(license.TargetName, fmt.Sprintf("%s #%d", license.Scope, license.TargetID))
	title, body, severity := "", "", "warning"
	switch license.Status {
	case store.LicenseStatusPastDue:
		title = fmt.Sprintf("License past due: %s", name)
		body = fmt.Sprintf("Protection keeps running. Pay the renewal before %s to avoid config lock.", license.CurrentPeriodEnd.Add(pastDueGrace).Format("2 Jan 2006"))
	case store.LicenseStatusCancelled:
		title = fmt.Sprintf("License ended: %s", name)
		if license.Scope == store.LicenseScopeSite {
			body = "The site license was cancelled. The site was removed from its edges and is no longer served. Place a new order to protect it again."
		} else {
			body = "The license was cancelled. Protection keeps its last configuration, but changes are locked. Place a new order to protect it again."
		}
	case store.LicenseStatusExpired:
		title = fmt.Sprintf("License expired: %s", name)
		if license.Scope == store.LicenseScopeSite {
			body = "The site license expired. The site was removed from its edges and is no longer served until renewed."
		} else {
			body = "Traffic is still protected with the last configuration, but changes are locked until the license is renewed."
		}
		severity = "critical"
	case store.LicenseStatusActive:
		if previous == "" {
			return
		}
		title = fmt.Sprintf("License active: %s", name)
		body = "The license is current again."
		severity = "info"
	default:
		return
	}
	if _, err := svc.notifications.Upsert(ctx, license.UserID, store.NotificationInput{
		EventKey: fmt.Sprintf("license-%d-%s-%d", license.ID, license.Status, license.CurrentPeriodEnd.Unix()),
		Kind:     "license",
		Severity: severity,
		Title:    title,
		Body:     body,
		Status:   license.Status,
		At:       time.Now().UTC(),
	}); err != nil {
		log.Printf("[api] license lifecycle: notify license=%d: %v", license.ID, err)
	}
}

// withLicenseGuard blocks customer writes that their licenses do not cover:
// direct edge/site creation (they are ordered), L4 or L7 control without that
// layer's license, moving or renaming a licensed site, and any config change on
// an expired or cancelled edge or site. Admins pass.
func withLicenseGuard(orders store.OrderStore, sites store.SiteStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isReadMethod(r.Method) || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		principal, ok := AuthPrincipalFromContext(r.Context())
		if !ok || principal.UserID <= 0 || strings.EqualFold(principal.Role, "Admin") {
			next.ServeHTTP(w, r)
			return
		}
		guard := licenseGuard{orders: orders, sites: sites}
		if code, message := guard.decide(r); code != 0 {
			writeErrorResponse(w, code, errorResponse{Error: licenseGuardErrorCode(code), Message: message})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func licenseGuardErrorCode(status int) string {
	if status == http.StatusLocked {
		return "license_expired"
	}
	return "license_required"
}

type licenseGuard struct {
	orders store.OrderStore
	sites  store.SiteStore
}

const (
	msgNoL4 = "This edge has no L4 license. Order the L4 protection add-on from Billing → Orders."
	msgNoL7 = "This edge has no L7 license, so it cannot run Athens or host sites. Order an edge with L7 from Billing → Orders."
)

func (g licenseGuard) decide(r *http.Request) (int, string) {
	ctx := r.Context()
	p := strings.TrimSuffix(r.URL.Path, "/")
	p = strings.TrimPrefix(p, "/api/v1")
	p = strings.TrimPrefix(p, "/api")
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(segs) == 0 {
		return 0, ""
	}
	switch segs[0] {
	case "servers":
		if len(segs) == 1 {
			if r.Method == http.MethodPost {
				return http.StatusPaymentRequired, "Edges are added through an order. Open Billing → Orders to order edge protection."
			}
			return 0, ""
		}
		id := parseAuditID(segs[1])
		if id <= 0 || r.Method == http.MethodDelete && len(segs) == 2 {
			return 0, ""
		}
		license, err := g.orders.LicenseFor(ctx, store.LicenseScopeServer, id)
		if err != nil {
			return 0, ""
		}
		if blocked, message := licenseLocked(license); blocked {
			return http.StatusLocked, message
		}
		if len(segs) < 3 {
			return 0, ""
		}
		switch layer := serverWriteLayer(r, segs[2]); {
		case layer == "l4" && !licenseHasL4(license.Kind):
			return http.StatusPaymentRequired, msgNoL4
		case layer == "l7" && !licenseHasL7(license.Kind):
			return http.StatusPaymentRequired, msgNoL7
		}
	case "sites":
		if len(segs) == 1 {
			if r.Method == http.MethodPost {
				return http.StatusPaymentRequired, "Sites are added through an order. Open Billing → Orders to order site protection."
			}
			return 0, ""
		}
		id := parseAuditID(segs[1])
		if id <= 0 || r.Method == http.MethodDelete && len(segs) == 2 {
			return 0, ""
		}
		license, err := g.orders.LicenseFor(ctx, store.LicenseScopeSite, id)
		if err != nil {
			return 0, ""
		}
		if blocked, message := licenseLocked(license); blocked {
			return http.StatusLocked, message
		}
		if len(segs) == 2 && (r.Method == http.MethodPut || r.Method == http.MethodPatch) {
			return g.checkSiteUpdate(r, id, license)
		}
	}
	return 0, ""
}

// serverWriteLayer maps an edge sub-resource to the protection layer it controls.
func serverWriteLayer(r *http.Request, resource string) string {
	switch {
	case strings.HasPrefix(resource, "l4"):
		return "l4"
	case resource == "l7-guard":
		return "l7"
	case resource == "service-control":
		var body serverServiceControlRequest
		if raw, ok := peekBody(r); ok && json.Unmarshal(raw, &body) == nil {
			switch strings.ToLower(strings.TrimSpace(body.Service)) {
			case "sparta":
				return "l4"
			case "athens":
				return "l7"
			}
		}
	}
	return ""
}

// checkSiteUpdate keeps a licensed site on what was paid for: the same domain,
// platform sites stay on platform edges, own-edge sites only move between the
// customer's own L7 edges.
func (g licenseGuard) checkSiteUpdate(r *http.Request, siteID int64, license store.License) (int, string) {
	raw, ok := peekBody(r)
	if !ok {
		return 0, ""
	}
	var payload store.SiteInput
	if json.Unmarshal(raw, &payload) != nil {
		return 0, ""
	}
	payload = payload.Normalize()
	existing, err := g.sites.Get(r.Context(), siteID)
	if err != nil {
		return 0, ""
	}
	if payload.Domain != "" && !strings.EqualFold(payload.Domain, existing.Domain) {
		return http.StatusPaymentRequired, "A site license covers one domain. Order the new domain as a site from Billing → Orders."
	}
	current := map[int64]bool{}
	for _, id := range existing.ServerIDs {
		current[id] = true
	}
	added := make([]int64, 0)
	for _, id := range uniqueInt64Slice(payload.ServerIDs) {
		if !current[id] {
			added = append(added, id)
		}
	}
	if len(added) == 0 {
		return 0, ""
	}
	if license.Kind == store.LicenseKindSitePlatform {
		return http.StatusPaymentRequired, "This site is served by Dorian platform edges and cannot be moved. Order it as an own-edge site to host it yourself."
	}
	for _, id := range added {
		edge, err := g.orders.LicenseFor(r.Context(), store.LicenseScopeServer, id)
		if err != nil || edge.UserID != license.UserID || !licenseHasL7(edge.Kind) {
			return http.StatusPaymentRequired, fmt.Sprintf("Edge #%d is not one of your L7 edges, so the site cannot be placed on it.", id)
		}
		if blocked, message := licenseLocked(edge); blocked {
			return http.StatusLocked, message
		}
	}
	return 0, ""
}

func licenseHasL4(kind string) bool {
	return kind == store.LicenseKindL4 || kind == store.LicenseKindUnified
}

func licenseHasL7(kind string) bool {
	return kind == store.LicenseKindL7 || kind == store.LicenseKindUnified
}

// peekBody reads the request body and puts it back for the next handler.
func peekBody(r *http.Request) ([]byte, bool) {
	if r.Body == nil {
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return raw, err == nil
}

func licenseLocked(license store.License) (bool, string) {
	switch license.Status {
	case store.LicenseStatusExpired:
		return true, fmt.Sprintf("The license for %s expired on %s. Protection keeps running, but changes are locked until it is renewed.",
			firstNonEmpty(license.TargetName, "this object"), license.CurrentPeriodEnd.Format("2 Jan 2006"))
	case store.LicenseStatusCancelled:
		return true, fmt.Sprintf("The license for %s was cancelled.", firstNonEmpty(license.TargetName, "this object"))
	}
	return false, ""
}
