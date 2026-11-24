package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

type licenseCancelPayload struct {
	Immediate bool `json:"immediate"`
}

// handleLicenseCancel ends a license at the end of its paid period (customers),
// or immediately (Admin with immediate=true). No refunds.
func (svc *orderService) handleLicenseCancel(w http.ResponseWriter, r *http.Request) {
	license, user, ok := svc.loadLicenseFor(w, r)
	if !ok {
		return
	}
	var payload licenseCancelPayload
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	if license.Status == store.LicenseStatusCancelled {
		writeError(w, http.StatusConflict, "this license is already cancelled")
		return
	}
	immediate := payload.Immediate && isAdminUser(user)
	if !immediate && license.CancelAtEnd {
		writeJSON(w, http.StatusOK, license)
		return
	}
	if err := svc.detachFromRenewal(r.Context(), license, user.ID); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	license, err := svc.orders.GetLicense(r.Context(), license.ID)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	previous := license.Status
	license.CancelAtEnd = true
	if immediate {
		license.Status = store.LicenseStatusCancelled
	}
	saved, err := svc.orders.SaveLicense(r.Context(), license)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	name := firstNonEmpty(saved.TargetName, fmt.Sprintf("%s #%d", saved.Scope, saved.TargetID))
	if immediate {
		svc.notifyLicenseStatus(r.Context(), saved, previous)
		svc.recordLicenseEvent(r.Context(), saved, store.LicenseEventCancelled,
			licenseEventTitle(store.LicenseEventCancelled, name),
			"License ended immediately. Place a new order to protect it again.")
		if saved.Scope == store.LicenseScopeSite {
			if err := svc.removeSiteTrafficAfterLicenseEnd(r.Context(), saved.TargetID); err != nil {
				log.Printf("[api] orders: site %d cancel cleanup: %v", saved.TargetID, err)
			}
		}
	} else {
		svc.notifyLicenseCancelScheduled(r.Context(), saved)
		svc.recordLicenseEvent(r.Context(), saved, store.LicenseEventCancelScheduled,
			licenseEventTitle(store.LicenseEventCancelScheduled, name),
			fmt.Sprintf("Active until %s, then ends. You can undo this before then.", saved.CurrentPeriodEnd.UTC().Format("2 Jan 2006")))
	}
	writeJSON(w, http.StatusOK, saved)
}

// removeSiteTrafficAfterLicenseEnd drops sites/<id>.dlic, deletes L7 Redis config on
// assigned edges, then clears panel edge assignment. Matches PANEL_EDGE_LICENSE_INTEGRATION §4
// ("Cancel site / remove from edge"). Failures are logged by callers; billing cancel still stands.
func (svc *orderService) removeSiteTrafficAfterLicenseEnd(ctx context.Context, siteID int64) error {
	if siteID <= 0 {
		return nil
	}
	if warns := deleteSiteLicenseOnAssignedEdges(ctx, svc.servers, svc.sites, siteID); len(warns) > 0 {
		log.Printf("[api] orders: site %d license delete warnings: %s", siteID, strings.Join(warns, "; "))
	}
	report, err := callL7DeleteSite(ctx, svc.servers, svc.sites, siteID)
	if err != nil {
		return err
	}
	for _, item := range report.Failed {
		log.Printf("[api] orders: site %d l7_delete_site failed edge=%d: %s", siteID, item.ServerID, item.Error)
	}
	for _, item := range report.Warnings {
		log.Printf("[api] orders: site %d l7_delete_site warning edge=%d: %s", siteID, item.ServerID, item.Error)
	}
	edgeIDs, _ := siteEdgeServerIDs(ctx, svc.sites, siteID)
	if err := svc.sites.UpdateSiteServers(ctx, siteID, nil); err != nil {
		return fmt.Errorf("clear site edges: %w", err)
	}
	if len(edgeIDs) > 0 && svc.siteListeningPorts != nil {
		if err := svc.siteListeningPorts.DeleteForServers(ctx, siteID, edgeIDs); err != nil {
			return fmt.Errorf("clear listening ports: %w", err)
		}
	}
	return nil
}

// handleLicenseResume undoes a scheduled cancellation.
func (svc *orderService) handleLicenseResume(w http.ResponseWriter, r *http.Request) {
	license, _, ok := svc.loadLicenseFor(w, r)
	if !ok {
		return
	}
	if license.Status == store.LicenseStatusCancelled {
		writeError(w, http.StatusConflict, "this license is already cancelled; place a new order to protect it again")
		return
	}
	if !license.CancelAtEnd {
		writeJSON(w, http.StatusOK, license)
		return
	}
	license.CancelAtEnd = false
	saved, err := svc.orders.SaveLicense(r.Context(), license)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	name := firstNonEmpty(saved.TargetName, fmt.Sprintf("%s #%d", saved.Scope, saved.TargetID))
	svc.recordLicenseEvent(r.Context(), saved, store.LicenseEventResumed,
		licenseEventTitle(store.LicenseEventResumed, name),
		"Scheduled cancellation was undone; the license will renew as usual.")
	writeJSON(w, http.StatusOK, saved)
}

func (svc *orderService) loadLicenseFor(w http.ResponseWriter, r *http.Request) (store.License, store.User, bool) {
	user, ok := principalOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return store.License{}, user, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "license not found")
		return store.License{}, user, false
	}
	license, err := svc.orders.GetLicense(r.Context(), id)
	if err != nil || (!isAdminUser(user) && license.UserID != user.ID) {
		writeError(w, http.StatusNotFound, "license not found")
		return store.License{}, user, false
	}
	return license, user, true
}

// detachFromRenewal takes a license out of its unpaid renewal order. The order is
// cancelled and, when other licenses remain, re-issued for them.
func (svc *orderService) detachFromRenewal(ctx context.Context, license store.License, actorID int64) error {
	if license.RenewalOrderID == nil {
		return nil
	}
	order, err := svc.orders.Get(ctx, *license.RenewalOrderID)
	if err != nil {
		if store.IsNotFound(err) {
			license.RenewalOrderID = nil
			_, err = svc.orders.SaveLicense(ctx, license)
		}
		return err
	}
	if order.Status != store.OrderStatusAwaitingPayment && order.Status != store.OrderStatusDraft {
		return nil
	}
	if order.PaidTotal > 0 {
		return fmt.Errorf("renewal order #%d already has a payment; contact support to cancel this license", order.ID)
	}
	remaining := make([]int64, 0, len(order.Details.RenewLicenseIDs))
	for _, id := range order.Details.RenewLicenseIDs {
		if id != license.ID {
			remaining = append(remaining, id)
		}
	}
	if _, err := svc.cancel(ctx, order, fmt.Sprintf("License #%d cancelled", license.ID)); err != nil {
		return err
	}
	if len(remaining) > 0 {
		if _, err := svc.createRenewalOrder(ctx, order.UserID, actorID, remaining, order.Period); err != nil {
			return fmt.Errorf("re-issue renewal for the other licenses: %w", err)
		}
	}
	return nil
}

func (svc *orderService) notifyLicenseCancelScheduled(ctx context.Context, license store.License) {
	if svc.notifications == nil || license.UserID <= 0 {
		return
	}
	name := firstNonEmpty(license.TargetName, fmt.Sprintf("%s #%d", license.Scope, license.TargetID))
	_, _ = svc.notifications.Upsert(ctx, license.UserID, store.NotificationInput{
		EventKey: fmt.Sprintf("license-%d-cancel-%d", license.ID, license.CurrentPeriodEnd.Unix()),
		Kind:     "license",
		Severity: "info",
		Title:    fmt.Sprintf("Cancellation scheduled: %s", name),
		Body:     fmt.Sprintf("The license stays active until %s and will not renew.", license.CurrentPeriodEnd.Format("2 Jan 2006")),
		Status:   "cancel_scheduled",
		At:       time.Now().UTC(),
	})
}
