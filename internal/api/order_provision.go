package api

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

// startProvisioning runs setup for an approved order in the background. Each
// finished step is saved on the order, so a retry continues where it stopped.
func (svc *orderService) startProvisioning(orderID int64) {
	if _, busy := svc.running.LoadOrStore(orderID, true); busy {
		return
	}
	go func() {
		defer svc.running.Delete(orderID)
		ctx := context.Background()
		if err := svc.provision(ctx, orderID); err != nil {
			log.Printf("[api] orders: provision order=%d failed: %v", orderID, err)
			order, loadErr := svc.orders.Get(ctx, orderID)
			if loadErr != nil {
				return
			}
			order.Error = err.Error()
			_ = svc.orders.Save(ctx, order)
			svc.notifyAdmins(ctx, order, "setup-failed", fmt.Sprintf("Setup of order #%d failed", orderID), err.Error())
		}
	}()
}

func (svc *orderService) provision(ctx context.Context, orderID int64) error {
	order, err := svc.orders.Get(ctx, orderID)
	if err != nil {
		return err
	}
	if order.Status != store.OrderStatusProvisioning {
		return nil
	}
	billing := billingPeriodForDeploy(order.Period)
	periodEnd := addPeriod(time.Now().UTC(), order.Period)
	if order.Details.CoTermEnd != nil && order.Details.CoTermEnd.After(time.Now()) {
		periodEnd = order.Details.CoTermEnd.UTC()
	}
	deployTimeout := svc.cfg.DeployLicenseTimeoutSeconds
	if deployTimeout <= 0 {
		deployTimeout = 900
	}

	for i := range order.Details.Edges {
		edge := &order.Details.Edges[i]
		if edge.ServerID > 0 {
			continue
		}
		opened := svc.orders.OpenSecrets(*edge)
		view, err := performServerCreate(ctx, svc.cfg, svc.servers, serverCreatePayload{
			Name:             edge.Name,
			IP:               edge.IP,
			LicenseType:      edgeLicenseKind(*edge),
			BillingPeriod:    billing,
			VersionUUID:      edge.VersionUUID,
			SSHUser:          edge.SSHUser,
			SSHPort:          edge.SSHPort,
			SSHAuthType:      edge.SSHAuthType,
			SSHPassword:      opened.SSHPassword,
			SSHPrivateKey:    opened.SSHPrivateKey,
			SSHKeyPassphrase: opened.SSHKeyPassphrase,
			UserIDs:          []int64{order.UserID},
		}, deployTimeout)
		if err != nil {
			edge.Error = err.Error()
			_ = svc.orders.Save(ctx, order)
			return fmt.Errorf("edge %s (%s): %w", edge.Name, edge.IP, err)
		}
		edge.ServerID = view.ID
		edge.Error = ""
		edge.SSHPassword, edge.SSHPrivateKey, edge.SSHKeyPassphrase = "", "", ""
		if _, err := svc.saveServerLicense(ctx, order, view.ID, edgeLicenseKind(*edge), periodEnd); err != nil {
			return err
		}
		if err := svc.orders.Save(ctx, order); err != nil {
			return err
		}
	}

	for _, serverID := range order.Details.UpgradeServerIDs {
		if containsID(order.Details.UpgradesDone, serverID) {
			continue
		}
		if _, err := performServerLicenseReissue(ctx, svc.cfg, svc.servers, serverID, store.LicenseKindUnified, billing); err != nil {
			return fmt.Errorf("L4 upgrade of edge #%d: %w", serverID, err)
		}
		license, err := svc.orders.LicenseFor(ctx, store.LicenseScopeServer, serverID)
		if err != nil {
			return fmt.Errorf("L4 upgrade of edge #%d: %w", serverID, err)
		}
		license.Kind = store.LicenseKindUnified
		if _, err := svc.orders.SaveLicense(ctx, license); err != nil {
			return err
		}
		_ = svc.orders.SetServerExpiry(ctx, serverID, license.CurrentPeriodEnd)
		order.Details.UpgradesDone = append(order.Details.UpgradesDone, serverID)
		if err := svc.orders.Save(ctx, order); err != nil {
			return err
		}
	}

	ownEdgeIDs := make([]int64, 0, len(order.Details.Edges))
	for _, edge := range order.Details.Edges {
		if edge.L7 && edge.ServerID > 0 {
			ownEdgeIDs = append(ownEdgeIDs, edge.ServerID)
		}
	}
	warnings := make([]string, 0)
	for i := range order.Details.Sites {
		site := &order.Details.Sites[i]
		if site.SiteID > 0 {
			continue
		}
		serverIDs := site.ServerIDs
		kind := store.LicenseKindSiteOwn
		if site.Placement == "platform" {
			serverIDs = order.Details.PlatformServerIDs
			kind = store.LicenseKindSitePlatform
		} else if len(serverIDs) == 0 {
			serverIDs = ownEdgeIDs
		}
		if len(serverIDs) == 0 {
			site.Error = "no edge to place the site on"
			_ = svc.orders.Save(ctx, order)
			return fmt.Errorf("site %s: no edge to place it on", site.Domain)
		}
		siteID, warning, err := svc.createOrderSite(ctx, *site, serverIDs)
		if err != nil {
			site.Error = err.Error()
			_ = svc.orders.Save(ctx, order)
			return fmt.Errorf("site %s: %w", site.Domain, err)
		}
		site.SiteID = siteID
		site.Error = warning
		if warning != "" {
			warnings = append(warnings, fmt.Sprintf("%s: %s", site.Domain, warning))
		}
		if _, err := svc.orders.SaveLicense(ctx, store.License{
			UserID: order.UserID, OrderID: &order.ID, Scope: store.LicenseScopeSite, TargetID: siteID,
			Kind: kind, Period: order.Period, Status: store.LicenseStatusActive, CurrentPeriodEnd: periodEnd,
		}); err != nil {
			return err
		}
		if err := svc.orders.Save(ctx, order); err != nil {
			return err
		}
	}

	now := time.Now().UTC()
	order.Status = store.OrderStatusActive
	order.ActivatedAt = &now
	order.Error = ""
	if len(warnings) > 0 {
		order.Note = strings.TrimSpace(order.Note + "\nSetup warnings: " + strings.Join(warnings, "; "))
	}
	if err := svc.orders.Save(ctx, order); err != nil {
		return err
	}
	svc.notify(ctx, order.UserID, order, "active", "info",
		fmt.Sprintf("Order #%d is live", order.ID),
		"Your edges and sites are set up and licensed.")
	return nil
}

func (svc *orderService) saveServerLicense(ctx context.Context, order store.Order, serverID int64, kind string, periodEnd time.Time) (store.License, error) {
	license, err := svc.orders.SaveLicense(ctx, store.License{
		UserID: order.UserID, OrderID: &order.ID, Scope: store.LicenseScopeServer, TargetID: serverID,
		Kind: kind, Period: order.Period, Status: store.LicenseStatusActive, CurrentPeriodEnd: periodEnd,
	})
	if err != nil {
		return license, err
	}
	_ = svc.orders.SetServerExpiry(ctx, serverID, periodEnd)
	return license, nil
}

// createOrderSite creates the site, its origin and pushes it to the edges. An edge
// sync failure is returned as a warning; the site and license still exist.
func (svc *orderService) createOrderSite(ctx context.Context, site store.OrderSite, serverIDs []int64) (int64, string, error) {
	input := store.SiteInput{Domain: site.Domain, Status: "ENABLE", ServerIDs: serverIDs}.Normalize()
	applySiteSslDefaults(&input)
	created, err := svc.sites.Create(ctx, input)
	if err != nil {
		if store.IsDuplicateDomain(err) {
			return 0, "", fmt.Errorf("domain already exists")
		}
		return 0, "", err
	}
	if err := svc.sites.UpdateSiteServers(ctx, created.ID, input.ServerIDs); err != nil {
		_ = svc.sites.Delete(ctx, created.ID)
		return 0, "", fmt.Errorf("assign edges: %w", err)
	}
	for _, origin := range normalizeOrderOrigins(site) {
		if _, err := svc.upstreams.Create(ctx, created.ID, store.UpstreamServerInput{
			Address: origin.Address, Protocol: origin.Protocol, Description: "origin from order", Status: "ENABLE",
		}); err != nil {
			_ = svc.sites.Delete(ctx, created.ID)
			return 0, "", fmt.Errorf("add origin %s: %w", origin.Address, err)
		}
	}
	report, err := callL7UpdateSite(ctx, svc.servers, svc.sites, created.ID, svc.l7Deps)
	if err != nil {
		return created.ID, "edge sync failed: " + err.Error(), nil
	}
	if _, err := applySiteEdgeSync(ctx, svc.sites, svc.siteListeningPorts, created.ID, report); err != nil {
		return created.ID, "edge sync failed: " + err.Error(), nil
	}
	if len(report.Failed) > 0 {
		return created.ID, fmt.Sprintf("%d edge(s) did not accept the site yet", len(report.Failed)), nil
	}
	return created.ID, "", nil
}

// applyRenewal extends every license in a paid renewal order and reissues edge
// license files in the background.
func (svc *orderService) applyRenewal(ctx context.Context, order store.Order) (store.Order, error) {
	now := time.Now().UTC()
	reissue := make([]store.License, 0)
	for _, id := range order.Details.RenewLicenseIDs {
		license, err := svc.orders.GetLicense(ctx, id)
		if err != nil {
			return order, err
		}
		start := license.CurrentPeriodEnd
		if start.Before(now) {
			start = now
		}
		license.CurrentPeriodEnd = addPeriod(start, order.Period)
		license.Period = order.Period
		license.Status = store.LicenseStatusActive
		license.RenewalOrderID = nil
		license.CancelAtEnd = false
		saved, err := svc.orders.SaveLicense(ctx, license)
		if err != nil {
			return order, err
		}
		if saved.Scope == store.LicenseScopeServer {
			_ = svc.orders.SetServerExpiry(ctx, saved.TargetID, saved.CurrentPeriodEnd)
			reissue = append(reissue, saved)
		}
	}
	order.Status = store.OrderStatusActive
	order.ActivatedAt = &now
	if err := svc.orders.Save(ctx, order); err != nil {
		return order, err
	}
	svc.notify(ctx, order.UserID, order, "renewed", "info",
		fmt.Sprintf("Renewal #%d applied", order.ID),
		fmt.Sprintf("%d license(s) extended.", len(order.Details.RenewLicenseIDs)))
	if len(reissue) > 0 {
		go svc.reissueEdgeLicenses(order.ID, reissue)
	}
	return svc.orders.Get(ctx, order.ID)
}

func (svc *orderService) reissueEdgeLicenses(orderID int64, licenses []store.License) {
	ctx := context.Background()
	failures := make([]string, 0)
	for _, license := range licenses {
		if _, err := performServerLicenseReissue(ctx, svc.cfg, svc.servers, license.TargetID, license.Kind, billingPeriodForDeploy(license.Period)); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", firstNonEmpty(license.TargetName, fmt.Sprintf("edge #%d", license.TargetID)), err))
			continue
		}
		_ = svc.orders.SetServerExpiry(ctx, license.TargetID, license.CurrentPeriodEnd)
	}
	if len(failures) == 0 {
		return
	}
	order, err := svc.orders.Get(ctx, orderID)
	if err != nil {
		return
	}
	order.Error = "License file reissue failed: " + strings.Join(failures, "; ")
	_ = svc.orders.Save(ctx, order)
	svc.notifyAdmins(ctx, order, "reissue-failed", fmt.Sprintf("Renewal #%d: edge license reissue failed", orderID), order.Error)
}

func containsID(ids []int64, id int64) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
