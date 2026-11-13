package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
	if immediate {
		svc.notifyLicenseStatus(r.Context(), saved, previous)
	} else {
		svc.notifyLicenseCancelScheduled(r.Context(), saved)
	}
	writeJSON(w, http.StatusOK, saved)
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
