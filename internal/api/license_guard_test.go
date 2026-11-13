package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"vue-project-backend/internal/store"
)

type guardOrders struct {
	store.OrderStore
	licenses map[string]store.License
}

func (g guardOrders) LicenseFor(_ context.Context, scope string, id int64) (store.License, error) {
	if license, ok := g.licenses[scope+":"+strconv.FormatInt(id, 10)]; ok {
		return license, nil
	}
	return store.License{}, context.Canceled
}

type guardSites struct {
	store.SiteStore
	sites map[int64]store.Site
}

func (g guardSites) Get(_ context.Context, id int64) (store.Site, error) {
	return g.sites[id], nil
}

func newTestGuard() licenseGuard {
	future := time.Now().Add(30 * 24 * time.Hour)
	lic := func(scope string, id int64, kind string, user int64) store.License {
		return store.License{Scope: scope, TargetID: id, Kind: kind, UserID: user, Status: store.LicenseStatusActive, CurrentPeriodEnd: future}
	}
	expired := lic("server", 5, store.LicenseKindUnified, 7)
	expired.Status = store.LicenseStatusExpired
	return licenseGuard{
		orders: guardOrders{licenses: map[string]store.License{
			"server:1": lic("server", 1, store.LicenseKindL4, 7),
			"server:2": lic("server", 2, store.LicenseKindL7, 7),
			"server:3": lic("server", 3, store.LicenseKindL7, 8),
			"server:5": expired,
			"site:10":  lic("site", 10, store.LicenseKindSiteOwn, 7),
			"site:11":  lic("site", 11, store.LicenseKindSitePlatform, 7),
		}},
		sites: guardSites{sites: map[int64]store.Site{
			10: {ID: 10, Domain: "shop.example.com", ServerIDs: []int64{2}},
			11: {ID: 11, Domain: "blog.example.com", ServerIDs: []int64{900}},
		}},
	}
}

func guardRequest(method, path, body string) *http.Request {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	return httptest.NewRequest(method, path, reader)
}

func TestLicenseGuardLayers(t *testing.T) {
	g := newTestGuard()
	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"create edge", http.MethodPost, "/api/v1/servers", "{}", http.StatusPaymentRequired},
		{"create site", http.MethodPost, "/sites", "{}", http.StatusPaymentRequired},
		{"l4 on L4 edge", http.MethodPut, "/servers/1/l4/options", "{}", 0},
		{"l4 on L7 edge", http.MethodPut, "/servers/2/l4/options", "{}", http.StatusPaymentRequired},
		{"l7 guard on L4 edge", http.MethodPut, "/servers/1/l7-guard", "{}", http.StatusPaymentRequired},
		{"l7 guard on L7 edge", http.MethodPut, "/servers/2/l7-guard", "{}", 0},
		{"stop sparta on L7 edge", http.MethodPost, "/servers/2/service-control", `{"service":"sparta","action":"stop"}`, http.StatusPaymentRequired},
		{"stop athens on L4 edge", http.MethodPost, "/servers/1/service-control", `{"service":"athens","action":"stop"}`, http.StatusPaymentRequired},
		{"restart angelos anywhere", http.MethodPost, "/servers/1/service-control", `{"service":"angelos","action":"start"}`, 0},
		{"expired edge locked", http.MethodPut, "/servers/5/l4/options", "{}", http.StatusLocked},
		{"delete expired edge", http.MethodDelete, "/servers/5", "", 0},
	}
	for _, tc := range cases {
		code, _ := g.decide(guardRequest(tc.method, tc.path, tc.body))
		if code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, code, tc.want)
		}
	}
}

func TestLicenseGuardSiteUpdate(t *testing.T) {
	g := newTestGuard()
	cases := []struct {
		name, path, body string
		want             int
	}{
		{"unchanged", "/sites/10", `{"domain":"shop.example.com","serverIds":[2]}`, 0},
		{"rename", "/sites/10", `{"domain":"other.example.com","serverIds":[2]}`, http.StatusPaymentRequired},
		{"move to own L4 edge", "/sites/10", `{"domain":"shop.example.com","serverIds":[2,1]}`, http.StatusPaymentRequired},
		{"move to someone else's edge", "/sites/10", `{"domain":"shop.example.com","serverIds":[3]}`, http.StatusPaymentRequired},
		{"drop an edge", "/sites/10", `{"domain":"shop.example.com","serverIds":[]}`, 0},
		{"platform site moved", "/sites/11", `{"domain":"blog.example.com","serverIds":[900,2]}`, http.StatusPaymentRequired},
	}
	for _, tc := range cases {
		req := guardRequest(http.MethodPut, tc.path, tc.body)
		code, _ := g.decide(req)
		if code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, code, tc.want)
		}
		if rest, _ := io.ReadAll(req.Body); string(rest) != tc.body {
			t.Errorf("%s: body not restored: %q", tc.name, rest)
		}
	}
}

func TestNextLicenseStatusCancelAtEnd(t *testing.T) {
	end := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	license := store.License{Status: store.LicenseStatusActive, CurrentPeriodEnd: end, CancelAtEnd: true}
	if got := nextLicenseStatus(license, end.Add(-time.Hour)); got != store.LicenseStatusActive {
		t.Fatalf("before end: %s", got)
	}
	if got := nextLicenseStatus(license, end.Add(time.Hour)); got != store.LicenseStatusCancelled {
		t.Fatalf("after end: %s", got)
	}
}
