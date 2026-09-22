package api

import (
	"errors"
	"strings"
	"testing"
)

func TestExtractDeployLicenseErrorDetail(t *testing.T) {
	raw := `{"code":5000,"description":"generate_license.sh failed","script_error":"could not obtain machine id from root@192.0.2.1:22: SSH test failed","message":"could not obtain machine id from root@192.0.2.1:22: SSH test failed"}`
	got := extractDeployLicenseErrorDetail(raw)
	if !strings.Contains(got, "could not obtain machine id") {
		t.Fatalf("expected script detail, got %q", got)
	}
}

func TestFormatDeployLicenseHTTPErrorLicenseNotFound(t *testing.T) {
	err := formatDeployLicenseHTTPError("deploy create_server", 404, []byte(`{"description":"license not found","req_id":"abc-123"}`))
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "license") {
		t.Fatalf("expected license guidance, got %q", msg)
	}
	if strings.Contains(msg, "{") {
		t.Fatalf("should not dump raw JSON: %q", msg)
	}
	var he *httpAPIErr
	if !errors.As(err, &he) {
		t.Fatalf("expected *httpAPIErr, got %T", err)
	}
	if he.detail.ReqID != "abc-123" {
		t.Fatalf("expected req_id propagated, got %#v", he.detail)
	}
	if strings.TrimSpace(he.detail.Hint) == "" {
		t.Fatal("expected hint on deploy error detail")
	}
}

func TestFormatDeployLicenseHTTPErrorEmptyBody(t *testing.T) {
	err := formatDeployLicenseHTTPError("deploy create_server", 502, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("expected status in message, got %q", err.Error())
	}
}
