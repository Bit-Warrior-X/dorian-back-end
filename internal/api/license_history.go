package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

type licenseHistoryResponse struct {
	License store.License               `json:"license"`
	Summary store.LicenseHistorySummary `json:"summary"`
	Events  []store.LicenseEvent        `json:"events"`
	Orders  []store.LicenseHistoryOrder `json:"orders"`
}

func (svc *orderService) handleLicenseHistory(w http.ResponseWriter, r *http.Request) {
	license, _, ok := svc.loadLicenseFor(w, r)
	if !ok {
		return
	}
	events, err := svc.orders.ListLicenseEventsForTarget(r.Context(), license.Scope, license.TargetID)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	if len(events) == 0 {
		_ = svc.backfillLicenseHistory(r.Context(), license)
		events, err = svc.orders.ListLicenseEventsForTarget(r.Context(), license.Scope, license.TargetID)
		if err != nil {
			writeOrderError(w, err)
			return
		}
	}
	orders, err := svc.orders.ListOrdersForTarget(r.Context(), license.UserID, license.Scope, license.TargetID)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	historyOrders := make([]store.LicenseHistoryOrder, 0, len(orders))
	for _, order := range orders {
		edgeNames := make([]string, 0)
		siteDomains := make([]string, 0)
		for _, edge := range order.Details.Edges {
			edgeNames = append(edgeNames, firstNonEmpty(edge.Name, edge.IP, fmt.Sprintf("edge #%d", edge.ServerID)))
		}
		for _, site := range order.Details.Sites {
			siteDomains = append(siteDomains, firstNonEmpty(site.Domain, fmt.Sprintf("site #%d", site.SiteID)))
		}
		historyOrders = append(historyOrders, store.LicenseHistoryOrder{
			ID:                order.ID,
			Kind:              order.Kind,
			Purpose:           order.Purpose,
			Status:            order.Status,
			Period:            order.Period,
			Currency:          order.Currency,
			Total:             order.Total,
			InvoiceNo:         order.InvoiceNo,
			Summary:           orderNotifySummary(order),
			PlatformServerIDs: append([]int64{}, order.Details.PlatformServerIDs...),
			EdgeNames:         edgeNames,
			SiteDomains:       siteDomains,
			CreatedAt:         order.CreatedAt,
			SubmittedAt:       order.SubmittedAt,
			PaidAt:            order.PaidAt,
			ActivatedAt:       order.ActivatedAt,
			CancelledAt:       order.CancelledAt,
		})
	}
	writeJSON(w, http.StatusOK, licenseHistoryResponse{
		License: license,
		Summary: buildLicenseHistorySummary(license, events, historyOrders),
		Events:  events,
		Orders:  historyOrders,
	})
}

func buildLicenseHistorySummary(license store.License, events []store.LicenseEvent, orders []store.LicenseHistoryOrder) store.LicenseHistorySummary {
	summary := store.LicenseHistorySummary{
		OrderCount: len(orders),
		Currency:   "USD",
	}
	for _, order := range orders {
		if order.Currency != "" {
			summary.Currency = order.Currency
		}
		switch order.Status {
		case store.OrderStatusActive:
			summary.CompletedOrders++
			summary.TotalSpent += order.Total
		case store.OrderStatusCancelled:
			summary.CancelledOrders++
		}
		if order.Kind == store.OrderKindRenewal {
			summary.RenewalOrders++
		}
	}
	var first *time.Time
	for _, event := range events {
		switch event.EventType {
		case store.LicenseEventCancelled, "order_cancelled":
			summary.CancelEvents++
		case store.LicenseEventReactivated:
			summary.Reactivations++
		}
		at := event.EventAt
		if first == nil || at.Before(*first) {
			t := at
			first = &t
		}
	}
	if first != nil {
		summary.FirstLicensedAt = first.UTC().Format(time.RFC3339)
	} else if !license.CreatedAt.IsZero() {
		summary.FirstLicensedAt = license.CreatedAt.UTC().Format(time.RFC3339)
	}
	if len(events) > 0 {
		summary.LastEventAt = events[0].EventAt.UTC().Format(time.RFC3339)
		summary.LastEventType = events[0].EventType
	}
	return summary
}

func (svc *orderService) recordLicenseEvent(ctx context.Context, license store.License, eventType, title, body string) {
	if svc.orders == nil || license.ID <= 0 {
		return
	}
	event := store.LicenseEvent{
		LicenseID: license.ID,
		UserID:    license.UserID,
		Scope:     license.Scope,
		TargetID:  license.TargetID,
		EventType: eventType,
		OrderID:   license.OrderID,
		Title:     title,
		Body:      body,
		EventAt:   time.Now().UTC(),
	}
	if err := svc.orders.AppendLicenseEvent(ctx, event); err != nil {
		log.Printf("[api] license history: append license=%d type=%s: %v", license.ID, eventType, err)
	}
}

func (svc *orderService) backfillLicenseHistory(ctx context.Context, license store.License) error {
	orders, err := svc.orders.ListOrdersForTarget(ctx, license.UserID, license.Scope, license.TargetID)
	if err != nil {
		return err
	}
	name := firstNonEmpty(license.TargetName, fmt.Sprintf("%s #%d", license.Scope, license.TargetID))
	// Oldest → newest so the first activation is "activated" and later ones are reactivations.
	for i := len(orders) - 1; i >= 0; i-- {
		order := orders[i]
		at := order.CreatedAt
		if order.ActivatedAt != nil {
			at = *order.ActivatedAt
		} else if order.PaidAt != nil {
			at = *order.PaidAt
		} else if order.SubmittedAt != nil {
			at = *order.SubmittedAt
		}
		eventType := store.LicenseEventActivated
		title := fmt.Sprintf("Licensed via order #%d", order.ID)
		body := orderNotifySummary(order)
		priorActive := false
		for j := i + 1; j < len(orders); j++ {
			if orders[j].Status == store.OrderStatusActive || orders[j].ActivatedAt != nil {
				priorActive = true
				break
			}
		}
		if order.Kind == store.OrderKindRenewal {
			eventType = store.LicenseEventRenewed
			title = fmt.Sprintf("Renewed via order #%d", order.ID)
		} else if priorActive {
			eventType = store.LicenseEventReactivated
			title = fmt.Sprintf("Re-ordered via order #%d", order.ID)
		}
		if order.Status == store.OrderStatusCancelled {
			eventType = "order_cancelled"
			title = fmt.Sprintf("Order #%d cancelled", order.ID)
			if order.CancelledAt != nil {
				at = *order.CancelledAt
			}
		}
		orderID := order.ID
		_ = svc.orders.AppendLicenseEvent(ctx, store.LicenseEvent{
			LicenseID: license.ID,
			UserID:    license.UserID,
			Scope:     license.Scope,
			TargetID:  license.TargetID,
			EventType: eventType,
			OrderID:   &orderID,
			Title:     title,
			Body:      firstNonEmpty(body, name),
			EventAt:   at,
		})
	}
	if license.Status == store.LicenseStatusCancelled || license.CancelAtEnd {
		eventType := store.LicenseEventCancelled
		title := fmt.Sprintf("License cancelled: %s", name)
		body := "License ended."
		if license.CancelAtEnd && license.Status != store.LicenseStatusCancelled {
			eventType = store.LicenseEventCancelScheduled
			title = fmt.Sprintf("Cancellation scheduled: %s", name)
			body = fmt.Sprintf("Will end on %s.", license.CurrentPeriodEnd.UTC().Format("2 Jan 2006"))
		}
		_ = svc.orders.AppendLicenseEvent(ctx, store.LicenseEvent{
			LicenseID: license.ID,
			UserID:    license.UserID,
			Scope:     license.Scope,
			TargetID:  license.TargetID,
			EventType: eventType,
			OrderID:   license.OrderID,
			Title:     title,
			Body:      body,
			EventAt:   license.UpdatedAt,
		})
	}
	return nil
}

func licenseEventTitle(eventType, name string) string {
	switch eventType {
	case store.LicenseEventActivated:
		return "License activated: " + name
	case store.LicenseEventReactivated:
		return "License re-activated: " + name
	case store.LicenseEventCancelled:
		return "License cancelled: " + name
	case store.LicenseEventCancelScheduled:
		return "Cancellation scheduled: " + name
	case store.LicenseEventResumed:
		return "Cancellation undone: " + name
	case store.LicenseEventRenewed:
		return "License renewed: " + name
	default:
		return strings.TrimSpace(eventType + " · " + name)
	}
}
