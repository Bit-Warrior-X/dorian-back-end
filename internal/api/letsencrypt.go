package api

import (
	"context"
	"strings"
	"time"

	"vue-project-backend/internal/acme"
	"vue-project-backend/internal/store"
)

func preserveManagedCertificates(existing store.Site, payload *store.SiteInput) {
	if payload == nil {
		return
	}
	sslType := strings.ToLower(strings.TrimSpace(payload.SslType))
	switch sslType {
	case "letsencrypt", "zerossl", "googletrust", "managed":
	default:
		return
	}
	if strings.TrimSpace(payload.SslCert) == "" {
		payload.SslCert = existing.SslCert
		payload.SslCertKey = existing.SslCertKey
	}
	if payload.CertificateExpiry == nil && existing.CertificateExpiry != nil {
		formatted := existing.CertificateExpiry.UTC().Format(time.RFC3339)
		payload.CertificateExpiry = &formatted
	}
}

func shouldIssueLetsEncrypt(existing *store.Site, next store.Site) bool {
	if !strings.EqualFold(strings.TrimSpace(next.SslType), "letsencrypt") {
		return false
	}
	if existing == nil {
		return true
	}
	if !strings.EqualFold(existing.SslType, "letsencrypt") {
		return true
	}
	if !sameSiteDomain(existing.Domain, next.Domain) {
		return true
	}
	if strings.TrimSpace(existing.SslCert) == "" || strings.TrimSpace(existing.SslCertKey) == "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(existing.CertificateStatus)) {
	case "failed", "expired", "none", "pending", "queued", "dns", "validating", "syncing":
		return true
	default:
		return false
	}
}

func isLetsEncryptIssuing(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "queued", "pending", "dns", "validating", "syncing":
		return true
	default:
		return false
	}
}

func enqueueLetsEncrypt(issuer *acme.Issuer, sites store.SiteStore, site store.Site) {
	if issuer == nil || !strings.EqualFold(site.SslType, "letsencrypt") {
		return
	}
	_ = sites.UpdateCertificateStatus(context.Background(), site.ID, "queued", "")
	issuer.Enqueue(site.ID)
}

func withLatestCertificate(ctx context.Context, sites store.SiteStore, site store.Site) store.Site {
	latest, err := sites.Get(ctx, site.ID)
	if err != nil {
		return site
	}
	site.CertificateStatus = latest.CertificateStatus
	site.CertificateExpiry = latest.CertificateExpiry
	site.CertificateError = latest.CertificateError
	site.SslCert = latest.SslCert
	site.SslCertKey = latest.SslCertKey
	return site
}
