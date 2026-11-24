package api

import (
	"strings"
	"testing"
	"time"

	"vue-project-backend/internal/store"
)

var testCatalog = []store.CatalogItem{
	{Code: store.CatalogEdgeL4, Title: "Edge L4", MonthlyPrice: 25, AnnualPrice: 240},
	{Code: store.CatalogEdgeL7, Title: "Edge L7", MonthlyPrice: 250, AnnualPrice: 2400},
	{Code: store.CatalogL4Addon, Title: "L4 add-on", MonthlyPrice: 99, AnnualPrice: 948},
	{Code: store.CatalogSiteOwn, Title: "Site own", MonthlyPrice: 10, AnnualPrice: 96},
	{Code: store.CatalogSitePlatform, Title: "Site platform", MonthlyPrice: 20, AnnualPrice: 192},
	{Code: store.CatalogSetupFee, Title: "Setup", MonthlyPrice: 50, OneTime: true},
}

func itemQty(items []store.OrderItem, code string) int {
	for _, item := range items {
		if item.Code == code {
			return item.Quantity
		}
	}
	return 0
}

func TestPriceOrderSiteOwnWithL4(t *testing.T) {
	order := store.Order{Kind: store.OrderKindNew, Purpose: store.OrderPurposeSiteOwn, Period: periodMonth}
	order.Details = normalizeOrderDetails(order.Purpose, store.OrderDetails{
		Edges: []store.OrderEdge{{Name: "a", IP: "1.1.1.1", L4: true}},
		Sites: []store.OrderSite{{Domain: "a.com", Origin: "2.2.2.2:80"}, {Domain: "b.com", Origin: "2.2.2.2:80"}, {Domain: "c.com", Origin: "2.2.2.2:80"}},
	})
	priceOrder(&order, testCatalog, nil, nil, time.Now())
	if itemQty(order.Items, store.CatalogEdgeL7) != 1 || itemQty(order.Items, store.CatalogL4Addon) != 1 ||
		itemQty(order.Items, store.CatalogSiteOwn) != 3 || itemQty(order.Items, store.CatalogSetupFee) != 1 {
		t.Fatalf("unexpected items: %+v", order.Items)
	}
	if order.Total != 250+99+30+50 {
		t.Fatalf("total = %v", order.Total)
	}
}

func TestPriceOrderExistingEdgeSkipsSetupFee(t *testing.T) {
	order := store.Order{Kind: store.OrderKindNew, Purpose: store.OrderPurposeEdge, Period: periodMonth}
	order.Details = normalizeOrderDetails(order.Purpose, store.OrderDetails{
		Edges: []store.OrderEdge{
			{Name: "new", IP: "1.1.1.1", SSHPassword: "x"},
			{Name: "reg", IP: "1.1.1.2", ServerID: 42},
		},
	})
	priceOrder(&order, testCatalog, nil, nil, time.Now())
	if itemQty(order.Items, store.CatalogEdgeL4) != 2 || itemQty(order.Items, store.CatalogSetupFee) != 1 {
		t.Fatalf("unexpected items: %+v", order.Items)
	}
}

func TestValidateOrderExistingTargetsSkipSSHAndOrigins(t *testing.T) {
	own := orderOwnership{l7ServerIDs: map[int64]bool{}, upgradeable: map[int64]bool{}}
	order := store.Order{Purpose: store.OrderPurposeEdgeSite, Details: normalizeOrderDetails(store.OrderPurposeEdgeSite, store.OrderDetails{
		Edges: []store.OrderEdge{{Name: "e", IP: "10.0.0.1", ServerID: 5}},
		Sites: []store.OrderSite{{Domain: "shop.example.com", SiteID: 9}},
	})}
	if err := validateOrderForSubmit(order, own, map[string]bool{"shop.example.com": true}); err != nil {
		t.Fatalf("existing edge+site should pass without SSH/origins: %v", err)
	}
}

func TestPriceOrderPurposes(t *testing.T) {
	edge := store.OrderEdge{Name: "a", IP: "1.1.1.1"}
	site := store.OrderSite{Domain: "a.com", Origin: "2.2.2.2"}
	cases := []struct {
		purpose string
		want    map[string]int
	}{
		{store.OrderPurposeEdge, map[string]int{store.CatalogEdgeL4: 2, store.CatalogSiteOwn: 0}},
		{store.OrderPurposeEdgeSite, map[string]int{store.CatalogEdgeL7: 2, store.CatalogL4Addon: 2, store.CatalogSiteOwn: 1}},
		{store.OrderPurposeSitePlatform, map[string]int{store.CatalogSitePlatform: 1, store.CatalogEdgeL4: 0, store.CatalogSetupFee: 0}},
	}
	for _, tc := range cases {
		order := store.Order{Kind: store.OrderKindNew, Purpose: tc.purpose, Period: periodYear}
		order.Details = normalizeOrderDetails(tc.purpose, store.OrderDetails{
			Edges: []store.OrderEdge{edge, {Name: "b", IP: "1.1.1.2"}},
			Sites: []store.OrderSite{site},
		})
		priceOrder(&order, testCatalog, nil, nil, time.Now())
		for code, qty := range tc.want {
			if got := itemQty(order.Items, code); got != qty {
				t.Errorf("%s: %s qty = %d, want %d", tc.purpose, code, got, qty)
			}
		}
	}
}

func TestPriceOrderAddonProrated(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := now.Add(time.Duration(365/2) * 24 * time.Hour)
	order := store.Order{Kind: store.OrderKindAddon, Purpose: store.OrderPurposeAddon, Period: periodYear}
	order.Details = normalizeOrderDetails(order.Purpose, store.OrderDetails{
		Sites:     []store.OrderSite{{Domain: "a.com", Origin: "x", Placement: "platform"}},
		CoTermEnd: &end,
	})
	priceOrder(&order, testCatalog, nil, nil, now)
	if len(order.Items) != 1 || order.Items[0].UnitPrice >= 192 || order.Items[0].UnitPrice < 90 {
		t.Fatalf("expected prorated platform site, got %+v", order.Items)
	}
}

func TestPriceRenewal(t *testing.T) {
	order := store.Order{Kind: store.OrderKindRenewal, Purpose: store.OrderPurposeRenewal, Period: periodYear}
	priceOrder(&order, testCatalog, []store.License{{Kind: store.LicenseKindUnified}, {Kind: store.LicenseKindSitePlatform}}, nil, time.Now())
	if order.Total != 2400+948+192 {
		t.Fatalf("renewal total = %v (%+v)", order.Total, order.Items)
	}
}

func TestPriceOrderSkipsCoveredExistingEdges(t *testing.T) {
	order := store.Order{Kind: store.OrderKindNew, Purpose: store.OrderPurposeSiteOwn, Period: periodMonth}
	order.Details = normalizeOrderDetails(order.Purpose, store.OrderDetails{
		Edges: []store.OrderEdge{{Name: "e", IP: "1.1.1.1", ServerID: 9, L7: true}},
		Sites: []store.OrderSite{{Domain: "a.com", Origin: "2.2.2.2", ServerIDs: []int64{9}}},
	})
	priceOrder(&order, testCatalog, nil, map[int64]bool{9: true}, time.Now())
	if got := itemQty(order.Items, store.CatalogEdgeL7); got != 0 {
		t.Fatalf("covered edge should not be billed, got EDGE_L7=%d items=%+v", got, order.Items)
	}
	if got := itemQty(order.Items, store.CatalogSiteOwn); got != 1 {
		t.Fatalf("site should still be billed, got SITE_OWN=%d", got)
	}
}

func TestValidateOrderForSubmit(t *testing.T) {
	own := orderOwnership{l7ServerIDs: map[int64]bool{7: true}, upgradeable: map[int64]bool{7: true}}
	base := func(purpose string, details store.OrderDetails) store.Order {
		return store.Order{Purpose: purpose, Details: normalizeOrderDetails(purpose, details)}
	}
	good := store.OrderEdge{Name: "e", IP: "10.0.0.1", SSHPassword: "x", HasSSHPassword: true}
	if err := validateOrderForSubmit(base(store.OrderPurposeEdge, store.OrderDetails{Edges: []store.OrderEdge{good}}), own, nil); err != nil {
		t.Fatalf("edge order: %v", err)
	}
	if err := validateOrderForSubmit(base(store.OrderPurposeSiteOwn, store.OrderDetails{Edges: []store.OrderEdge{good}}), own, nil); err == nil {
		t.Fatal("site_own without sites must fail")
	}
	noPass := store.OrderEdge{Name: "e", IP: "10.0.0.1"}
	if err := validateOrderForSubmit(base(store.OrderPurposeEdge, store.OrderDetails{Edges: []store.OrderEdge{noPass}}), own, nil); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("missing password: %v", err)
	}
	dup := map[string]bool{"taken.com": true}
	err := validateOrderForSubmit(base(store.OrderPurposeSitePlatform, store.OrderDetails{Sites: []store.OrderSite{{Domain: "taken.com", Origin: "1.1.1.1"}}}), own, dup)
	if err == nil || !strings.Contains(err.Error(), "already protected") {
		t.Fatalf("duplicate domain: %v", err)
	}
	addon := base(store.OrderPurposeAddon, store.OrderDetails{Sites: []store.OrderSite{{Domain: "n.com", Origin: "1.1.1.1", Placement: "own", ServerIDs: []int64{9}}}})
	if err := validateOrderForSubmit(addon, own, nil); err == nil {
		t.Fatal("addon site on a foreign edge must fail")
	}
	addon = base(store.OrderPurposeAddon, store.OrderDetails{UpgradeServerIDs: []int64{7}})
	if err := validateOrderForSubmit(addon, own, nil); err != nil {
		t.Fatalf("L4 upgrade of own L7 edge: %v", err)
	}
}

func TestNextLicenseStatus(t *testing.T) {
	end := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	license := store.License{Status: store.LicenseStatusActive, CurrentPeriodEnd: end}
	if got := nextLicenseStatus(license, end.Add(-time.Hour)); got != store.LicenseStatusActive {
		t.Fatalf("before end: %s", got)
	}
	if got := nextLicenseStatus(license, end.Add(24*time.Hour)); got != store.LicenseStatusPastDue {
		t.Fatalf("after end: %s", got)
	}
	if got := nextLicenseStatus(license, end.Add(15*24*time.Hour)); got != store.LicenseStatusExpired {
		t.Fatalf("after grace: %s", got)
	}
	license.Status = store.LicenseStatusCancelled
	if got := nextLicenseStatus(license, end.Add(-time.Hour)); got != store.LicenseStatusCancelled {
		t.Fatalf("cancelled stays: %s", got)
	}
}
