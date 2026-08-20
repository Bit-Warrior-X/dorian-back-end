package acme

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"vue-project-backend/internal/config"
)

type dns01Provider interface {
	Present(ctx context.Context, domain, fqdn, value string) error
	CleanUp(ctx context.Context, domain, fqdn, value string) error
	Resolver() string
}

func newDNS01Provider(cfg config.Config, internal *internalDNS) (dns01Provider, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.AcmeDNSProvider))
	if provider == "" {
		provider = detectDNSProvider(cfg)
	}
	switch provider {
	case "rfc2136":
		return newRFC2136Provider(cfg)
	case "cloudflare":
		return newCloudflareProvider(cfg)
	case "httpreq":
		return newHTTPReqProvider(cfg)
	case "internal":
		if internal == nil {
			return nil, fmt.Errorf("internal DNS-01 listener is not configured (set acme.dnsListen)")
		}
		return internal, nil
	case "":
		return nil, fmt.Errorf("no DNS-01 provider configured; set acme.dnsProvider to rfc2136, cloudflare, httpreq, or internal")
	default:
		return nil, fmt.Errorf("unsupported ACME DNS provider %q", provider)
	}
}

func detectDNSProvider(cfg config.Config) string {
	switch {
	case strings.TrimSpace(cfg.AcmeCloudflareAPIToken) != "":
		return "cloudflare"
	case strings.TrimSpace(cfg.AcmeRFC2136Nameserver) != "":
		return "rfc2136"
	case strings.TrimSpace(cfg.AcmeHTTPReqEndpoint) != "":
		return "httpreq"
	case strings.TrimSpace(cfg.AcmeDNSListen) != "":
		return "internal"
	default:
		return ""
	}
}

func challengeFQDN(domain string) string {
	host := strings.ToLower(strings.TrimSpace(domain))
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimSuffix(host, ".")
	return "_acme-challenge." + host + "."
}

func dnsAliasFQDN(cfg config.Config) string {
	alias := strings.ToLower(strings.TrimSpace(cfg.AcmeDNSAlias))
	if alias == "" {
		return ""
	}
	return strings.TrimSuffix(alias, ".") + "."
}

func txtPublishFQDN(cfg config.Config, domain string) string {
	if alias := dnsAliasFQDN(cfg); alias != "" {
		return alias
	}
	return challengeFQDN(domain)
}

func waitForTXT(ctx context.Context, fqdn, value, nameserver string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	fqdn = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	value = strings.TrimSpace(value)
	deadline := time.Now().Add(timeout)

	// Prefer public resolvers so we observe what Let's Encrypt is likely to see.
	nameservers := make([]string, 0, 3)
	if trimmed := strings.TrimSpace(nameserver); trimmed != "" {
		nameservers = append(nameservers, trimmed)
	}
	for _, ns := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		if !containsString(nameservers, ns) {
			nameservers = append(nameservers, ns)
		}
	}

	var lastErr error
	for {
		matched := 0
		for _, ns := range nameservers {
			records, err := txtResolver(ns).LookupTXT(ctx, fqdn)
			if err != nil {
				lastErr = err
				continue
			}
			found := false
			for _, record := range records {
				if strings.TrimSpace(record) == value {
					found = true
					break
				}
			}
			if found {
				matched++
				continue
			}
			lastErr = fmt.Errorf("TXT %s via %s has %q (want challenge value)", fqdn, ns, strings.Join(records, ","))
		}
		// Require agreement from at least two resolvers (or one if only one configured).
		need := 2
		if len(nameservers) < 2 {
			need = 1
		}
		if matched >= need {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("DNS-01 TXT %s not visible: %w", fqdn, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func txtResolver(nameserver string) *net.Resolver {
	nameserver = strings.TrimSpace(nameserver)
	if nameserver == "" {
		return net.DefaultResolver
	}
	if _, _, err := net.SplitHostPort(nameserver); err != nil {
		nameserver = net.JoinHostPort(nameserver, "53")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, nameserver)
		},
	}
}
