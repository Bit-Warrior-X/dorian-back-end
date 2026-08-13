package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	acmelib "golang.org/x/crypto/acme"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

const issueTimeout = 8 * time.Minute
const renewBefore = 30 * 24 * time.Hour

type AfterIssueFunc func(ctx context.Context, siteID int64) error

type Issuer struct {
	cfg        config.Config
	sites      store.SiteStore
	afterIssue AfterIssueFunc
	queue      chan int64
	inflight   sync.Map
	provider   dns01Provider
	internal   *internalDNS
	accountKey *ecdsa.PrivateKey
}

func NewIssuer(cfg config.Config, sites store.SiteStore) *Issuer {
	return &Issuer{
		cfg:      cfg,
		sites:    sites,
		queue:    make(chan int64, 64),
		internal: newInternalDNS(cfg.AcmeDNSListen),
	}
}

func (i *Issuer) SetAfterIssue(fn AfterIssueFunc) {
	if i == nil {
		return
	}
	i.afterIssue = fn
}

func (i *Issuer) Enqueue(siteID int64) {
	if i == nil || siteID <= 0 {
		return
	}
	select {
	case i.queue <- siteID:
	default:
		log.Printf("acme queue full; dropping site %d", siteID)
	}
}

func (i *Issuer) Start(ctx context.Context) {
	if i == nil {
		return
	}
	key, err := loadOrCreateAccountKey(i.cfg.AcmeAccountKeyPath)
	if err != nil {
		log.Printf("acme account key: %v", err)
	} else {
		i.accountKey = key
	}
	provider, err := newDNS01Provider(i.cfg, i.internal)
	if err != nil {
		log.Printf("acme dns-01 provider: %v", err)
	} else {
		i.provider = provider
		name := strings.ToLower(strings.TrimSpace(i.cfg.AcmeDNSProvider))
		if name == "" {
			name = detectDNSProvider(i.cfg)
		}
		log.Printf("acme dns-01 provider ready (%s)", name)
	}
	if i.internal != nil {
		i.internal.Start(ctx)
	}
	go i.worker(ctx)
	go i.renewLoop(ctx)
}

func (i *Issuer) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case siteID := <-i.queue:
			i.issueSite(ctx, siteID)
		}
	}
}

func (i *Issuer) renewLoop(ctx context.Context) {
	interval := time.Duration(i.cfg.AcmeRenewIntervalHours) * time.Hour
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			i.enqueueDue(ctx)
			timer.Reset(interval)
		}
	}
}

func (i *Issuer) enqueueDue(ctx context.Context) {
	list, err := i.sites.List(ctx)
	if err != nil {
		log.Printf("acme renew list sites: %v", err)
		return
	}
	now := time.Now()
	for _, site := range list {
		if !strings.EqualFold(site.SslType, "letsencrypt") {
			continue
		}
		if siteNeedsIssuance(site, now) {
			i.Enqueue(site.ID)
		}
	}
}

func siteNeedsIssuance(site store.Site, now time.Time) bool {
	status := strings.ToLower(strings.TrimSpace(site.CertificateStatus))
	if strings.TrimSpace(site.SslCert) == "" || strings.TrimSpace(site.SslCertKey) == "" {
		return true
	}
	switch status {
	case "pending", "queued", "dns", "validating", "syncing", "failed", "expired", "none":
		return true
	}
	if site.CertificateExpiry == nil {
		return true
	}
	return !site.CertificateExpiry.After(now.Add(renewBefore))
}

func (i *Issuer) issueSite(parent context.Context, siteID int64) {
	if _, loaded := i.inflight.LoadOrStore(siteID, struct{}{}); loaded {
		return
	}
	defer i.inflight.Delete(siteID)

	ctx, cancel := context.WithTimeout(parent, issueTimeout)
	defer cancel()

	site, err := i.sites.Get(ctx, siteID)
	if err != nil {
		log.Printf("acme load site %d: %v", siteID, err)
		return
	}
	if !strings.EqualFold(site.SslType, "letsencrypt") {
		return
	}
	domain := normalizeDomain(site.Domain)
	if domain == "" {
		i.setStatus(ctx, siteID, "failed", "site domain is empty")
		return
	}
	i.setStatus(ctx, siteID, "queued", "")

	certPEM, keyPEM, expiry, err := i.obtain(ctx, siteID, domain)
	if err != nil {
		log.Printf("acme issue %s (site %d): %v", domain, siteID, err)
		i.setStatus(context.Background(), siteID, "failed", err.Error())
		return
	}
	if err := i.sites.UpdateCertificate(ctx, siteID, string(certPEM), string(keyPEM), "syncing", expiry); err != nil {
		log.Printf("acme store cert site %d: %v", siteID, err)
		i.setStatus(context.Background(), siteID, "failed", err.Error())
		return
	}
	log.Printf("acme issued certificate for %s (site %d), expires %s", domain, siteID, expiry.Format(time.RFC3339))
	var pushErr error
	if i.afterIssue != nil {
		pushErr = i.afterIssue(ctx, siteID)
		if pushErr != nil {
			log.Printf("acme push cert to edges for site %d: %v", siteID, pushErr)
		}
	}
	status := certStatusForExpiry(expiry, time.Now())
	errMsg := ""
	if pushErr != nil {
		errMsg = "certificate issued, but edge sync failed: " + pushErr.Error()
	}
	i.setStatus(ctx, siteID, status, errMsg)
}

func (i *Issuer) setStatus(ctx context.Context, siteID int64, status, errMsg string) {
	if err := i.sites.UpdateCertificateStatus(ctx, siteID, status, errMsg); err != nil {
		log.Printf("acme status %s site %d: %v", status, siteID, err)
	}
}

func (i *Issuer) obtain(ctx context.Context, siteID int64, domain string) ([]byte, []byte, *time.Time, error) {
	if i.accountKey == nil {
		return nil, nil, nil, fmt.Errorf("acme account key is not available")
	}
	if i.provider == nil {
		return nil, nil, nil, fmt.Errorf("acme DNS-01 provider is not configured")
	}
	email := strings.TrimSpace(i.cfg.AcmeEmail)
	if email == "" {
		return nil, nil, nil, fmt.Errorf("acme email is required")
	}

	client := &acmelib.Client{
		Key:          i.accountKey,
		DirectoryURL: strings.TrimSpace(i.cfg.AcmeDirectoryURL),
	}
	if client.DirectoryURL == "" {
		client.DirectoryURL = acmelib.LetsEncryptURL
	}

	account := &acmelib.Account{Contact: []string{"mailto:" + email}}
	if _, err := client.Register(ctx, account, acmelib.AcceptTOS); err != nil && !errors.Is(err, acmelib.ErrAccountAlreadyExists) {
		return nil, nil, nil, fmt.Errorf("register acme account: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, acmelib.DomainIDs(domain))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("authorize order: %w", err)
	}

	type presentedChallenge struct {
		domain string
		fqdn   string
		value  string
	}
	var presented []presentedChallenge
	defer func() {
		for _, item := range presented {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_ = i.provider.CleanUp(cleanupCtx, item.domain, item.fqdn, item.value)
			cancel()
		}
	}()

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("get authorization: %w", err)
		}
		if authz.Status == acmelib.StatusValid {
			continue
		}
		var challenge *acmelib.Challenge
		for _, item := range authz.Challenges {
			if item.Type == "dns-01" {
				challenge = item
				break
			}
		}
		if challenge == nil {
			return nil, nil, nil, fmt.Errorf("authorization for %s has no DNS-01 challenge", authz.Identifier.Value)
		}
		value, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("dns-01 record: %w", err)
		}
		ident := strings.TrimPrefix(authz.Identifier.Value, "*.")
		publishFQDN := txtPublishFQDN(i.cfg, ident)
		i.setStatus(ctx, siteID, "dns", "")
		if err := i.provider.Present(ctx, ident, publishFQDN, value); err != nil {
			return nil, nil, nil, fmt.Errorf("publish dns-01 TXT %s: %w", strings.TrimSuffix(publishFQDN, "."), err)
		}
		presented = append(presented, presentedChallenge{domain: ident, fqdn: publishFQDN, value: value})
		i.setStatus(ctx, siteID, "validating", "")

		wait := time.Duration(i.cfg.AcmeDNSPropagationSeconds) * time.Second
		if wait <= 0 {
			wait = 3 * time.Second
		}
		if wait > 8*time.Second {
			wait = 8 * time.Second
		}
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		case <-time.After(wait):
		}
		if _, err := client.Accept(ctx, challenge); err != nil {
			return nil, nil, nil, fmt.Errorf("accept dns-01 challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return nil, nil, nil, fmt.Errorf("wait authorization: %w", err)
		}
	}

	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return nil, nil, nil, fmt.Errorf("wait order: %w", err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return nil, nil, nil, err
	}
	ders, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	if len(ders) == 0 {
		return nil, nil, nil, fmt.Errorf("acme returned an empty certificate")
	}
	parsed, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	keyPEM, err := encodePrivateKey(certKey)
	if err != nil {
		return nil, nil, nil, err
	}
	expiry := parsed.NotAfter.UTC()
	return encodeCertificates(ders), keyPEM, &expiry, nil
}

func certStatusForExpiry(expiry *time.Time, now time.Time) string {
	if expiry == nil {
		return "none"
	}
	if !expiry.After(now) {
		return "expired"
	}
	if !expiry.After(now.Add(renewBefore)) {
		return "expiring"
	}
	return "valid"
}

func normalizeDomain(value string) string {
	domain := strings.ToLower(strings.TrimSpace(value))
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	if slash := strings.Index(domain, "/"); slash >= 0 {
		domain = domain[:slash]
	}
	return strings.TrimSuffix(domain, ".")
}
