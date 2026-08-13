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
		timeout = 30 * time.Second
	}
	fqdn = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	deadline := time.Now().Add(timeout)
	resolver := txtResolver(nameserver)
	var lastErr error
	for {
		records, err := resolver.LookupTXT(ctx, fqdn)
		if err == nil {
			for _, record := range records {
				if strings.TrimSpace(record) == value {
					return nil
				}
			}
			lastErr = fmt.Errorf("TXT %s does not contain the challenge value yet", fqdn)
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("DNS-01 TXT %s not visible: %w", fqdn, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
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
