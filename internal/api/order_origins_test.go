package api

import (
	"strings"
	"testing"

	"vue-project-backend/internal/store"
)

func TestNormalizeOrderOrigins(t *testing.T) {
	legacy := normalizeOrderOrigins(store.OrderSite{Origin: " 10.0.0.1:80 ", OriginProtocol: "HTTPS"})
	if len(legacy) != 1 || legacy[0].Address != "10.0.0.1:80" || legacy[0].Protocol != "https" {
		t.Fatalf("legacy origin: %+v", legacy)
	}
	many := normalizeOrderOrigins(store.OrderSite{Origins: []store.OrderOrigin{
		{Address: "a.example.com", Protocol: "http"},
		{Address: "A.example.com ", Protocol: "x"},
		{Address: "", Protocol: "https"},
		{Address: "a.example.com", Protocol: "https"},
	}})
	if len(many) != 2 || many[1].Protocol != "https" {
		t.Fatalf("dedupe: %+v", many)
	}
}

func TestValidOriginAddress(t *testing.T) {
	for _, ok := range []string{"10.0.0.1", "10.0.0.1:8080", "origin.example.com", "origin:443", "[2001:db8::1]:80", "2001:db8::1"} {
		if !validOriginAddress(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"http://x.com", "x.com:0", "x.com:99999", "bad host", "-x.com"} {
		if validOriginAddress(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestValidateOrderNeedsOrigins(t *testing.T) {
	order := store.Order{Purpose: store.OrderPurposeSitePlatform}
	order.Details = normalizeOrderDetails(order.Purpose, store.OrderDetails{Sites: []store.OrderSite{{Domain: "shop.example.com"}}})
	err := validateOrderForSubmit(order, orderOwnership{}, nil)
	if err == nil || !strings.Contains(err.Error(), "origin") {
		t.Fatalf("want origin error, got %v", err)
	}
	order.Details.Sites[0].Origins = []store.OrderOrigin{{Address: "10.0.0.1", Protocol: "http"}, {Address: "10.0.0.2:8080", Protocol: "https"}}
	if err := validateOrderForSubmit(order, orderOwnership{}, nil); err != nil {
		t.Fatalf("valid order: %v", err)
	}
}
