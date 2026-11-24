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
			body := err.Error() + " · " + orderNotifySummary(order)
			svc.notify(ctx, order.UserID, order, "setup-failed", "warning",
				fmt.Sprintf("Order #%d setup did not finish", orderID),
				"We could not complete setup yet. Our team has been notified. "+body)
			svc.notifyAdmins(ctx, order, "setup-failed", fmt.Sprintf("Setup of order #%d failed", orderID), body)
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
		kind := edgeLicenseKind(*edge)
		if edge.ServerID > 0 {
			if lic, err := svc.orders.LicenseFor(ctx, store.LicenseScopeServer, edge.ServerID); err == nil &&
				lic.OrderID != nil && *lic.OrderID == order.ID && lic.Status == store.LicenseStatusActive {
				continue
			} else if err != nil && !store.IsNotFound(err) {
				return err
			}
			view, err := svc.servers.GetView(ctx, edge.ServerID)
			if err != nil {
				edge.Error = err.Error()
				_ = svc.orders.Save(ctx, order)
				return fmt.Errorf("edge #%d: %w", edge.ServerID, err)
			}
			if !userAssignedToServer(view, order.UserID) {
				userIDs := append([]int64{}, view.ManagedUserIds...)
				userIDs = append(userIDs, order.UserID)
				if err := svc.servers.UpdateServerUsers(ctx, edge.ServerID, uniquePositiveIDs(userIDs)); err != nil {
					return fmt.Errorf("edge %s: assign customer: %w", firstNonEmpty(edge.Name, view.Name), err)
				}
			}
			edge.Name = firstNonEmpty(edge.Name, view.Name)
			edge.IP = firstNonEmpty(edge.IP, view.IP)
			edge.Error = ""
			// Already-licensed edges listed as site hosts (site_own / edge_site) are
			// placement-only — do not reissue or extend their period.
			if lic, err := svc.orders.LicenseFor(ctx, store.LicenseScopeServer, edge.ServerID); err == nil &&
				licenseStillCovers(lic) && edgeLicenseCovers(lic.Kind, kind) {
				if err := svc.orders.Save(ctx, order); err != nil {
					return err
				}
				continue
			} else if err != nil && !store.IsNotFound(err) {
				return err
			}
			expireAt := periodEnd
			if _, err := performServerLicenseReissue(ctx, svc.cfg, svc.servers, edge.ServerID, kind, billing, &expireAt); err != nil {
				edge.Error = err.Error()
				_ = svc.orders.Save(ctx, order)
				return fmt.Errorf("edge %s: license existing edge: %w", firstNonEmpty(edge.Name, view.Name), err)
			}
			if _, err := svc.saveServerLicense(ctx, order, edge.ServerID, kind, periodEnd); err != nil {
				return err
			}
			if err := svc.orders.Save(ctx, order); err != nil {
				return err
			}
			continue
		}
		opened := svc.orders.OpenSecrets(*edge)
		expireAt := periodEnd
		view, err := performServerCreate(ctx, svc.cfg, svc.servers, serverCreatePayload{
			Name:             edge.Name,
			IP:               edge.IP,
			LicenseType:      kind,
			BillingPeriod:    billing,
			VersionUUID:      edge.VersionUUID,
			SSHUser:          edge.SSHUser,
			SSHPort:          edge.SSHPort,
			SSHAuthType:      edge.SSHAuthType,
			SSHPassword:      opened.SSHPassword,
			SSHPrivateKey:    opened.SSHPrivateKey,
			SSHKeyPassphrase: opened.SSHKeyPassphrase,
			UserIDs:          []int64{order.UserID},
			ExpireAt:         &expireAt,
		}, deployTimeout)
		if err != nil {
			edge.Error = err.Error()
			_ = svc.orders.Save(ctx, order)
			return fmt.Errorf("edge %s (%s): %w", edge.Name, edge.IP, err)
		}
		edge.ServerID = view.ID
		edge.Error = ""
		edge.SSHPassword, edge.SSHPrivateKey, edge.SSHKeyPassphrase = "", "", ""
		if _, err := svc.saveServerLicense(ctx, order, view.ID, kind, periodEnd); err != nil {
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
		license, err := svc.orders.LicenseFor(ctx, store.LicenseScopeServer, serverID)
		if err != nil {
			return fmt.Errorf("L4 upgrade of edge #%d: %w", serverID, err)
		}
		expireAt := license.CurrentPeriodEnd
		if expireAt.Before(time.Now()) {
			expireAt = periodEnd
		}
		if _, err := performServerLicenseReissue(ctx, svc.cfg, svc.servers, serverID, store.LicenseKindUnified, billing, &expireAt); err != nil {
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
		kind := store.LicenseKindSiteOwn
		if site.Placement == "platform" {
			kind = store.LicenseKindSitePlatform
		}
		if site.SiteID > 0 {
			if lic, err := svc.orders.LicenseFor(ctx, store.LicenseScopeSite, site.SiteID); err == nil &&
				lic.OrderID != nil && *lic.OrderID == order.ID && lic.Status == store.LicenseStatusActive {
				existing, getErr := svc.sites.Get(ctx, site.SiteID)
				// Skip only when this order already placed the site on at least one edge.
				if getErr == nil && len(existing.ServerIDs) > 0 && strings.TrimSpace(site.Error) == "" {
					continue
				}
			} else if err != nil && !store.IsNotFound(err) {
				return err
			}
			existing, err := svc.sites.Get(ctx, site.SiteID)
			if err != nil {
				site.Error = err.Error()
				_ = svc.orders.Save(ctx, order)
				return fmt.Errorf("site #%d: %w", site.SiteID, err)
			}
			site.Domain = firstNonEmpty(site.Domain, existing.Domain)
			serverIDs := existing.ServerIDs
			if site.Placement == "platform" {
				if len(order.Details.PlatformServerIDs) > 0 {
					serverIDs = order.Details.PlatformServerIDs
				}
			} else if len(serverIDs) == 0 {
				serverIDs = site.ServerIDs
				if len(serverIDs) == 0 {
					serverIDs = ownEdgeIDs
				}
			}
			if len(serverIDs) == 0 {
				site.Error = "no edge to place the site on"
				_ = svc.orders.Save(ctx, order)
				return fmt.Errorf("site %s: no edge to place it on", site.Domain)
			}
			if err := svc.sites.UpdateSiteServers(ctx, site.SiteID, serverIDs); err != nil {
				return fmt.Errorf("site %s: assign edges: %w", site.Domain, err)
			}
			// Reactivate / bind the panel license before edge install + L7 push so
			// re-orders after cancel are not treated as still cancelled.
			prevStatus := ""
			if prev, err := svc.orders.LicenseFor(ctx, store.LicenseScopeSite, site.SiteID); err == nil {
				prevStatus = prev.Status
			}
			savedLic, err := svc.orders.SaveLicense(ctx, store.License{
				UserID: order.UserID, OrderID: &order.ID, Scope: store.LicenseScopeSite, TargetID: site.SiteID,
				Kind: kind, Period: order.Period, Status: store.LicenseStatusActive, CurrentPeriodEnd: periodEnd,
				CancelAtEnd: false,
			})
			if err != nil {
				return err
			}
			svc.recordSiteOrEdgeLicenseActivation(ctx, savedLic, order, prevStatus)
			if warning := svc.installSiteLicenseAndPushL7(ctx, site.SiteID, kind, periodEnd); warning != "" {
				log.Printf("[api] orders: existing site %d: %s", site.SiteID, warning)
				warnings = append(warnings, fmt.Sprintf("%s: %s", site.Domain, warning))
				site.Error = warning
			} else {
				site.Error = ""
			}
			if err := svc.orders.Save(ctx, order); err != nil {
				return err
			}
			continue
		}
		serverIDs := site.ServerIDs
		if site.Placement == "platform" {
			serverIDs = order.Details.PlatformServerIDs
		} else if len(serverIDs) == 0 {
			serverIDs = ownEdgeIDs
		}
		if len(serverIDs) == 0 {
			site.Error = "no edge to place the site on"
			_ = svc.orders.Save(ctx, order)
			return fmt.Errorf("site %s: no edge to place it on", site.Domain)
		}
		siteID, warning, err := svc.createOrderSite(ctx, *site, serverIDs, kind, periodEnd)
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
		savedLic, err := svc.orders.SaveLicense(ctx, store.License{
			UserID: order.UserID, OrderID: &order.ID, Scope: store.LicenseScopeSite, TargetID: siteID,
			Kind: kind, Period: order.Period, Status: store.LicenseStatusActive, CurrentPeriodEnd: periodEnd,
		})
		if err != nil {
			return err
		}
		svc.recordSiteOrEdgeLicenseActivation(ctx, savedLic, order, "")
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
	summary := orderNotifySummary(order)
	svc.notify(ctx, order.UserID, order, "completed", "info",
		fmt.Sprintf("Order #%d completed", order.ID),
		"Setup finished — your protection is licensed and live. "+summary)
	svc.notifyAdmins(ctx, order, "completed",
		fmt.Sprintf("Order #%d completed", order.ID),
		summary)
	return nil
}

func (svc *orderService) saveServerLicense(ctx context.Context, order store.Order, serverID int64, kind string, periodEnd time.Time) (store.License, error) {
	prevStatus := ""
	if prev, err := svc.orders.LicenseFor(ctx, store.LicenseScopeServer, serverID); err == nil {
		prevStatus = prev.Status
	}
	license, err := svc.orders.SaveLicense(ctx, store.License{
		UserID: order.UserID, OrderID: &order.ID, Scope: store.LicenseScopeServer, TargetID: serverID,
		Kind: kind, Period: order.Period, Status: store.LicenseStatusActive, CurrentPeriodEnd: periodEnd,
		CancelAtEnd: false,
	})
	if err != nil {
		return license, err
	}
	_ = svc.orders.SetServerExpiry(ctx, serverID, periodEnd)
	svc.recordSiteOrEdgeLicenseActivation(ctx, license, order, prevStatus)
	return license, nil
}

func (svc *orderService) recordSiteOrEdgeLicenseActivation(ctx context.Context, license store.License, order store.Order, previousStatus string) {
	name := firstNonEmpty(license.TargetName, fmt.Sprintf("%s #%d", license.Scope, license.TargetID))
	eventType := store.LicenseEventActivated
	title := licenseEventTitle(store.LicenseEventActivated, name)
	body := fmt.Sprintf("Order #%d · %s", order.ID, orderNotifySummary(order))
	if previousStatus == store.LicenseStatusCancelled || previousStatus == store.LicenseStatusExpired {
		eventType = store.LicenseEventReactivated
		title = licenseEventTitle(store.LicenseEventReactivated, name)
		body = fmt.Sprintf("Re-ordered on #%d after %s. %s", order.ID, previousStatus, orderNotifySummary(order))
	}
	orderID := order.ID
	license.OrderID = &orderID
	svc.recordLicenseEvent(ctx, license, eventType, title, body)
}

// createOrderSite creates the site, its origin, installs sites/<id>.dlic on each
// edge, then pushes L7 config. An edge sync failure is returned as a warning;
// the site still exists.
func (svc *orderService) createOrderSite(ctx context.Context, site store.OrderSite, serverIDs []int64, licenseKind string, periodEnd time.Time) (int64, string, error) {
	input := store.SiteInput{Domain: site.Domain, Status: "ENABLE", ServerIDs: serverIDs}.Normalize()
	if err := store.ApplyDefaultProtectionWafID(ctx, svc.db, &input); err != nil {
		return 0, "", fmt.Errorf("default protection profile: %w", err)
	}
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
	warning := svc.installSiteLicenseAndPushL7(ctx, created.ID, licenseKind, periodEnd)
	if warning != "" {
		log.Printf("[api] orders: site %d: %s", created.ID, warning)
	}
	return created.ID, warning, nil
}

// installSiteLicenseAndPushL7 posts sites/<id>.dlic on assigned edges, then always
// pushes full site config via l7_update_site. License/L7 issues are returned as a
// warning string so the site/license row can still be saved.
func (svc *orderService) installSiteLicenseAndPushL7(ctx context.Context, siteID int64, kind string, periodEnd time.Time) string {
	parts := make([]string, 0, 2)
	if warns := installSiteLicenseOnAssignedEdges(ctx, svc.servers, svc.sites, siteID, kind, store.LicenseStatusActive, periodEnd); len(warns) > 0 {
		parts = append(parts, strings.Join(warns, "; "))
	}
	report, err := callL7UpdateSite(ctx, svc.servers, svc.sites, siteID, svc.l7Deps)
	if err != nil {
		parts = append(parts, "edge sync failed: "+formatL7StatusForOperator(err))
		return strings.Join(parts, "; ")
	}
	if _, err := applySiteEdgeSync(ctx, svc.sites, svc.siteListeningPorts, siteID, report); err != nil {
		parts = append(parts, "edge sync failed: "+err.Error())
		return strings.Join(parts, "; ")
	}
	if len(report.Failed) > 0 {
		failed := make([]string, 0, len(report.Failed))
		for _, item := range report.Failed {
			failed = append(failed, formatL7StatusForOperator(fmt.Errorf("%s", item.Error)))
		}
		parts = append(parts, fmt.Sprintf("%d edge(s) did not accept the site yet: %s", len(report.Failed), strings.Join(failed, "; ")))
	}
	return strings.Join(parts, "; ")
}

// applyRenewal extends every license in a paid renewal order and reissues edge
// / site license files in the background.
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
		}
		reissue = append(reissue, saved)
	}
	order.Status = store.OrderStatusActive
	order.ActivatedAt = &now
	if err := svc.orders.Save(ctx, order); err != nil {
		return order, err
	}
	names := make([]string, 0, len(reissue))
	for _, license := range reissue {
		names = append(names, firstNonEmpty(license.TargetName, fmt.Sprintf("%s #%d", license.Scope, license.TargetID)))
		name := firstNonEmpty(license.TargetName, fmt.Sprintf("%s #%d", license.Scope, license.TargetID))
		orderID := order.ID
		license.OrderID = &orderID
		svc.recordLicenseEvent(ctx, license, store.LicenseEventRenewed,
			licenseEventTitle(store.LicenseEventRenewed, name),
			fmt.Sprintf("Extended through %s via renewal #%d.", license.CurrentPeriodEnd.UTC().Format("2 Jan 2006"), order.ID))
	}
	detail := fmt.Sprintf("%d license(s) extended through %s", len(reissue), periodEndLabel(reissue))
	if len(names) > 0 {
		detail += ": " + strings.Join(names, ", ")
	}
	if purchase := orderNotifySummary(order); purchase != "" && !strings.Contains(detail, purchase) {
		detail += " · " + purchase
	}
	svc.notify(ctx, order.UserID, order, "completed", "info",
		fmt.Sprintf("Renewal #%d completed", order.ID),
		detail)
	svc.notifyAdmins(ctx, order, "completed",
		fmt.Sprintf("Renewal #%d completed", order.ID),
		detail)
	if len(reissue) > 0 {
		go svc.reissueLicensesOnEdges(order.ID, reissue)
	}
	return svc.orders.Get(ctx, order.ID)
}

func periodEndLabel(licenses []store.License) string {
	if len(licenses) == 0 {
		return "the new period"
	}
	end := licenses[0].CurrentPeriodEnd
	for _, license := range licenses[1:] {
		if license.CurrentPeriodEnd.After(end) {
			end = license.CurrentPeriodEnd
		}
	}
	return end.UTC().Format("2 Jan 2006")
}

func (svc *orderService) reissueLicensesOnEdges(orderID int64, licenses []store.License) {
	ctx := context.Background()
	failures := make([]string, 0)
	for _, license := range licenses {
		expireAt := license.CurrentPeriodEnd
		switch license.Scope {
		case store.LicenseScopeServer:
			if _, err := performServerLicenseReissue(ctx, svc.cfg, svc.servers, license.TargetID, license.Kind, billingPeriodForDeploy(license.Period), &expireAt); err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", firstNonEmpty(license.TargetName, fmt.Sprintf("edge #%d", license.TargetID)), err))
				continue
			}
			_ = svc.orders.SetServerExpiry(ctx, license.TargetID, license.CurrentPeriodEnd)
		case store.LicenseScopeSite:
			if warning := svc.installSiteLicenseAndPushL7(ctx, license.TargetID, license.Kind, expireAt); warning != "" {
				failures = append(failures, fmt.Sprintf("%s: %s", firstNonEmpty(license.TargetName, fmt.Sprintf("site #%d", license.TargetID)), warning))
			}
		}
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
	svc.notify(ctx, order.UserID, order, "reissue-failed", "warning",
		fmt.Sprintf("Renewal #%d needs attention", orderID),
		"Licenses were extended in billing, but updating files on some edges failed. "+order.Error)
	svc.notifyAdmins(ctx, order, "reissue-failed", fmt.Sprintf("Renewal #%d: license file reissue failed", orderID), order.Error)
}

func containsID(ids []int64, id int64) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
