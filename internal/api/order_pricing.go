package api

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

const (
	periodMonth = "month"
	periodYear  = "year"
)

func normalizeOrderPeriod(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "month", "monthly", "mo":
		return periodMonth
	default:
		return periodYear
	}
}

func periodDays(period string) int {
	if period == periodMonth {
		return 30
	}
	return 365
}

func addPeriod(from time.Time, period string) time.Time {
	if period == periodMonth {
		return from.AddDate(0, 1, 0)
	}
	return from.AddDate(1, 0, 0)
}

// billingPeriodForDeploy maps order periods to deploy_license billing periods.
func billingPeriodForDeploy(period string) string {
	if period == periodMonth {
		return "monthly"
	}
	return "annual"
}

// edgeLicenseKind is the server license created for an order edge.
func edgeLicenseKind(edge store.OrderEdge) string {
	switch {
	case edge.L7 && edge.L4:
		return store.LicenseKindUnified
	case edge.L7:
		return store.LicenseKindL7
	default:
		return store.LicenseKindL4
	}
}

// catalogCodesForLicense lists the price codes that renew one license.
func catalogCodesForLicense(kind string) []string {
	switch kind {
	case store.LicenseKindL4:
		return []string{store.CatalogEdgeL4}
	case store.LicenseKindL7:
		return []string{store.CatalogEdgeL7}
	case store.LicenseKindUnified:
		return []string{store.CatalogEdgeL7, store.CatalogL4Addon}
	case store.LicenseKindSitePlatform:
		return []string{store.CatalogSitePlatform}
	default:
		return []string{store.CatalogSiteOwn}
	}
}

type orderLineBuilder struct {
	catalog map[string]store.CatalogItem
	period  string
	factor  float64
	order   []string
	lines   map[string]*store.OrderItem
}

func newOrderLineBuilder(catalog []store.CatalogItem, period string, factor float64) *orderLineBuilder {
	byCode := make(map[string]store.CatalogItem, len(catalog))
	for _, item := range catalog {
		byCode[item.Code] = item
	}
	if factor <= 0 || factor > 1 {
		factor = 1
	}
	return &orderLineBuilder{catalog: byCode, period: period, factor: factor, lines: map[string]*store.OrderItem{}}
}

func (b *orderLineBuilder) add(code string, quantity int) {
	if quantity <= 0 {
		return
	}
	item, ok := b.catalog[code]
	if !ok {
		return
	}
	unit := item.AnnualPrice
	if b.period == periodMonth || item.OneTime {
		unit = item.MonthlyPrice
	}
	if item.OneTime && unit <= 0 {
		return
	}
	note := ""
	if !item.OneTime && b.factor < 1 {
		unit = roundCents(unit * b.factor)
		note = fmt.Sprintf("prorated %.0f%%", b.factor*100)
	}
	line, ok := b.lines[code]
	if !ok {
		line = &store.OrderItem{Code: code, Label: item.Title, UnitPrice: unit, Note: note}
		b.lines[code] = line
		b.order = append(b.order, code)
	}
	line.Quantity += quantity
	line.LineTotal = roundCents(line.UnitPrice * float64(line.Quantity))
}

func (b *orderLineBuilder) result() ([]store.OrderItem, float64) {
	items := make([]store.OrderItem, 0, len(b.order))
	total := 0.0
	for _, code := range b.order {
		items = append(items, *b.lines[code])
		total += b.lines[code].LineTotal
	}
	return items, roundCents(total)
}

func roundCents(value float64) float64 {
	return math.Round(value*100) / 100
}

// prorateFactor is the share of a billing period left until coTermEnd.
func prorateFactor(coTermEnd *time.Time, period string, now time.Time) float64 {
	if coTermEnd == nil {
		return 1
	}
	remaining := coTermEnd.Sub(now).Hours() / 24
	if remaining <= 0 {
		return 1
	}
	factor := remaining / float64(periodDays(period))
	if factor > 1 {
		return 1
	}
	return math.Max(factor, 0.01)
}

// priceOrder rebuilds the order lines and total from its details. renewals holds the
// licenses named in Details.RenewLicenseIDs. coveredEdgeIDs are existing edges that
// already have an active license covering this order — they are not billed again.
func priceOrder(order *store.Order, catalog []store.CatalogItem, renewals []store.License, coveredEdgeIDs map[int64]bool, now time.Time) {
	factor := 1.0
	if order.Kind == store.OrderKindAddon {
		factor = prorateFactor(order.Details.CoTermEnd, order.Period, now)
	}
	b := newOrderLineBuilder(catalog, order.Period, factor)
	setupEdges := 0
	for _, edge := range order.Details.Edges {
		if edge.ServerID == 0 {
			setupEdges++
		}
		if edge.ServerID > 0 && coveredEdgeIDs[edge.ServerID] {
			continue
		}
		switch edgeLicenseKind(edge) {
		case store.LicenseKindUnified:
			b.add(store.CatalogEdgeL7, 1)
			b.add(store.CatalogL4Addon, 1)
		case store.LicenseKindL7:
			b.add(store.CatalogEdgeL7, 1)
		default:
			b.add(store.CatalogEdgeL4, 1)
		}
	}
	b.add(store.CatalogL4Addon, len(order.Details.UpgradeServerIDs))
	for _, site := range order.Details.Sites {
		if site.Placement == "platform" {
			b.add(store.CatalogSitePlatform, 1)
		} else {
			b.add(store.CatalogSiteOwn, 1)
		}
	}
	for _, license := range renewals {
		for _, code := range catalogCodesForLicense(license.Kind) {
			b.add(code, 1)
		}
	}
	// Setup fee only for edges we still need to install (not already registered).
	b.add(store.CatalogSetupFee, setupEdges)
	order.Items, order.Total = b.result()
}

const maxOrderOrigins = 16

// validOriginAddress accepts host, IP, host:port, [v6]:port.
func validOriginAddress(address string) bool {
	host, port := address, ""
	if h, p, err := net.SplitHostPort(address); err == nil {
		host, port = h, p
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return orderHostPattern.MatchString(host)
}

var orderHostPattern = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

var orderDomainPattern = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// normalizeOrderDetails trims inputs and applies the purpose defaults
// (which layers an edge gets, where sites are placed).
func normalizeOrderDetails(purpose string, details store.OrderDetails) store.OrderDetails {
	edges := make([]store.OrderEdge, 0, len(details.Edges))
	for _, edge := range details.Edges {
		edge.Name = strings.TrimSpace(edge.Name)
		edge.IP = strings.TrimSpace(edge.IP)
		edge.SSHUser = strings.TrimSpace(edge.SSHUser)
		edge.SSHPort = strings.TrimSpace(edge.SSHPort)
		if edge.SSHPort == "" {
			edge.SSHPort = "22"
		}
		if edge.SSHUser == "" {
			edge.SSHUser = "root"
		}
		if strings.TrimSpace(edge.SSHAuthType) != store.SSHAuthKey {
			edge.SSHAuthType = store.SSHAuthPassword
		}
		switch purpose {
		case store.OrderPurposeEdge:
			edge.L4, edge.L7 = true, false
		case store.OrderPurposeEdgeSite:
			edge.L4, edge.L7 = true, true
		case store.OrderPurposeSiteOwn:
			edge.L7 = true
		}
		if !edge.L4 && !edge.L7 {
			edge.L4 = true
		}
		edges = append(edges, edge)
	}
	sites := make([]store.OrderSite, 0, len(details.Sites))
	for _, site := range details.Sites {
		site.Domain = strings.ToLower(strings.TrimSpace(site.Domain))
		site.Origins = normalizeOrderOrigins(site)
		site.Origin, site.OriginProtocol = "", "http"
		if len(site.Origins) > 0 {
			site.Origin, site.OriginProtocol = site.Origins[0].Address, site.Origins[0].Protocol
		}
		switch purpose {
		case store.OrderPurposeSitePlatform:
			site.Placement = "platform"
		case store.OrderPurposeSiteOwn, store.OrderPurposeEdgeSite:
			site.Placement = "own"
		default:
			if site.Placement != "platform" {
				site.Placement = "own"
			}
		}
		if site.Placement == "platform" {
			site.ServerIDs = nil
		}
		if site.SiteID == 0 && site.Domain == "" && len(site.Origins) == 0 {
			continue
		}
		sites = append(sites, site)
	}
	details.Edges = edges
	details.Sites = sites
	details.UpgradeServerIDs = uniquePositiveIDs(details.UpgradeServerIDs)
	details.RenewLicenseIDs = uniquePositiveIDs(details.RenewLicenseIDs)
	details.PlatformServerIDs = uniquePositiveIDs(details.PlatformServerIDs)
	needsPlatform := false
	for _, site := range sites {
		if site.Placement == "platform" {
			needsPlatform = true
			break
		}
	}
	if !needsPlatform {
		details.PlatformServerIDs = nil
	}
	if purpose == store.OrderPurposeSitePlatform {
		details.Edges = []store.OrderEdge{}
	}
	if purpose == store.OrderPurposeEdge {
		details.Sites = []store.OrderSite{}
	}
	return details
}

// normalizeOrderOrigins trims and de-duplicates origins, falling back to the legacy
// single origin field.
func normalizeOrderOrigins(site store.OrderSite) []store.OrderOrigin {
	raw := site.Origins
	if len(raw) == 0 && strings.TrimSpace(site.Origin) != "" {
		raw = []store.OrderOrigin{{Address: site.Origin, Protocol: site.OriginProtocol}}
	}
	out := make([]store.OrderOrigin, 0, len(raw))
	seen := map[string]bool{}
	for _, origin := range raw {
		origin.Address = strings.TrimSpace(origin.Address)
		if strings.EqualFold(strings.TrimSpace(origin.Protocol), "https") {
			origin.Protocol = "https"
		} else {
			origin.Protocol = "http"
		}
		key := origin.Protocol + "://" + strings.ToLower(origin.Address)
		if origin.Address == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, origin)
	}
	return out
}

func uniquePositiveIDs(ids []int64) []int64 {
	seen := make(map[int64]bool, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// orderOwnership is what a customer already holds; add-on orders may only target it.
type orderOwnership struct {
	l7ServerIDs map[int64]bool // own edges that can host sites (L7 / Unified)
	upgradeable map[int64]bool // own L7 edges that can take the L4 add-on
}

// validateOrderForSubmit enforces the per-purpose rules before an order is priced and locked.
func validateOrderForSubmit(order store.Order, own orderOwnership, existingDomains map[string]bool) error {
	d := order.Details
	edgeCount, siteCount := len(d.Edges), len(d.Sites)
	switch order.Purpose {
	case store.OrderPurposeEdge:
		if edgeCount == 0 {
			return fmt.Errorf("add at least one edge to protect")
		}
	case store.OrderPurposeSiteOwn, store.OrderPurposeEdgeSite:
		if edgeCount == 0 {
			return fmt.Errorf("add the edge that will host your sites")
		}
		if siteCount == 0 {
			return fmt.Errorf("add at least one site")
		}
	case store.OrderPurposeSitePlatform:
		if siteCount == 0 {
			return fmt.Errorf("add at least one site")
		}
	case store.OrderPurposeAddon:
		if edgeCount == 0 && siteCount == 0 && len(d.UpgradeServerIDs) == 0 {
			return fmt.Errorf("add an edge, a site, or an L4 upgrade")
		}
	case store.OrderPurposeRenewal:
		if len(d.RenewLicenseIDs) == 0 {
			return fmt.Errorf("select the licenses to renew")
		}
		return nil
	default:
		return fmt.Errorf("unknown order purpose %q", order.Purpose)
	}
	seenIPs := map[string]bool{}
	seenServerIDs := map[int64]bool{}
	for i, edge := range d.Edges {
		label := fmt.Sprintf("edge %d", i+1)
		if edge.ServerID > 0 {
			if seenServerIDs[edge.ServerID] {
				return fmt.Errorf("%s: edge #%d is listed twice", label, edge.ServerID)
			}
			seenServerIDs[edge.ServerID] = true
			if edge.IP != "" {
				if seenIPs[edge.IP] {
					return fmt.Errorf("%s: IP %s is listed twice", label, edge.IP)
				}
				seenIPs[edge.IP] = true
			}
			continue
		}
		if edge.Name == "" {
			return fmt.Errorf("%s: name is required", label)
		}
		if net.ParseIP(edge.IP) == nil {
			return fmt.Errorf("%s: a valid IP address is required", label)
		}
		if seenIPs[edge.IP] {
			return fmt.Errorf("%s: IP %s is listed twice", label, edge.IP)
		}
		seenIPs[edge.IP] = true
		if edge.SSHAuthType == store.SSHAuthKey {
			if !edge.HasSSHKey && strings.TrimSpace(edge.SSHPrivateKey) == "" {
				return fmt.Errorf("%s: SSH private key is required", label)
			}
		} else if !edge.HasSSHPassword && strings.TrimSpace(edge.SSHPassword) == "" {
			return fmt.Errorf("%s: SSH password is required", label)
		}
	}
	newL7Edges := 0
	for _, edge := range d.Edges {
		if edge.L7 {
			newL7Edges++
		}
	}
	seenDomains := map[string]bool{}
	seenSiteIDs := map[int64]bool{}
	for i, site := range d.Sites {
		label := fmt.Sprintf("site %d", i+1)
		if site.SiteID > 0 {
			if seenSiteIDs[site.SiteID] {
				return fmt.Errorf("%s: site #%d is listed twice", label, site.SiteID)
			}
			seenSiteIDs[site.SiteID] = true
			if site.Domain != "" {
				if seenDomains[site.Domain] {
					return fmt.Errorf("%s: %s is listed twice", label, site.Domain)
				}
				seenDomains[site.Domain] = true
			}
			continue
		}
		if !orderDomainPattern.MatchString(site.Domain) {
			return fmt.Errorf("%s: %q is not a valid domain", label, site.Domain)
		}
		if seenDomains[site.Domain] {
			return fmt.Errorf("%s: %s is listed twice", label, site.Domain)
		}
		seenDomains[site.Domain] = true
		if existingDomains[site.Domain] {
			return fmt.Errorf("%s: %s is already protected", label, site.Domain)
		}
		if len(site.Origins) == 0 {
			return fmt.Errorf("%s: add at least one origin server", label)
		}
		if len(site.Origins) > maxOrderOrigins {
			return fmt.Errorf("%s: at most %d origin servers", label, maxOrderOrigins)
		}
		for _, origin := range site.Origins {
			if !validOriginAddress(origin.Address) {
				return fmt.Errorf("%s: origin %q must be a host or IP, optionally with :port", label, origin.Address)
			}
		}
		if site.Placement == "own" {
			if newL7Edges == 0 && len(site.ServerIDs) == 0 {
				return fmt.Errorf("%s: choose an edge of yours that runs L7, or place it on the platform", label)
			}
			for _, id := range site.ServerIDs {
				if !own.l7ServerIDs[id] {
					return fmt.Errorf("%s: edge #%d is not one of your L7 edges", label, id)
				}
			}
		}
	}
	for _, id := range d.UpgradeServerIDs {
		if !own.upgradeable[id] {
			return fmt.Errorf("edge #%d cannot take the L4 add-on (it must be your L7 edge)", id)
		}
	}
	return nil
}
