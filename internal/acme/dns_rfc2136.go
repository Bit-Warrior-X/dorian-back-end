package acme

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"vue-project-backend/internal/config"
)

type rfc2136Provider struct {
	nameserver string
	tsigKey    string
	tsigSecret string
	tsigAlgo   string
	zone       string
}

func newRFC2136Provider(cfg config.Config) (*rfc2136Provider, error) {
	nameserver := strings.TrimSpace(cfg.AcmeRFC2136Nameserver)
	if nameserver == "" {
		return nil, fmt.Errorf("rfc2136 nameserver is required")
	}
	if _, _, err := net.SplitHostPort(nameserver); err != nil {
		nameserver = net.JoinHostPort(nameserver, "53")
	}
	algo := rfc2136Algorithm(cfg.AcmeRFC2136TSIGAlgorithm)
	key := strings.TrimSpace(cfg.AcmeRFC2136TSIGKey)
	if key != "" {
		key = dns.Fqdn(key)
	}
	return &rfc2136Provider{
		nameserver: nameserver,
		tsigKey:    key,
		tsigSecret: strings.TrimSpace(cfg.AcmeRFC2136TSIGSecret),
		tsigAlgo:   algo,
		zone:       strings.TrimSpace(cfg.AcmeRFC2136Zone),
	}, nil
}

func (p *rfc2136Provider) Present(_ context.Context, domain, fqdn, value string) error {
	return p.update(domain, fqdn, value, true)
}

func (p *rfc2136Provider) CleanUp(_ context.Context, domain, fqdn, value string) error {
	return p.update(domain, fqdn, value, false)
}

func (p *rfc2136Provider) Resolver() string {
	return p.nameserver
}

func (p *rfc2136Provider) update(domain, fqdn, value string, insert bool) error {
	rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN TXT %q", dns.Fqdn(fqdn), value))
	if err != nil {
		return fmt.Errorf("rfc2136 record: %w", err)
	}

	var lastErr error
	for _, zone := range p.zoneCandidates(domain, fqdn) {
		msg := new(dns.Msg)
		msg.SetUpdate(zone)
		if insert {
			msg.Insert([]dns.RR{rr})
		} else {
			msg.Remove([]dns.RR{rr})
		}
		client := &dns.Client{Timeout: 10 * time.Second}
		if p.tsigKey != "" && p.tsigSecret != "" {
			client.TsigSecret = map[string]string{p.tsigKey: p.tsigSecret}
			msg.SetTsig(p.tsigKey, p.tsigAlgo, 300, time.Now().Unix())
		}
		resp, _, err := client.Exchange(msg, p.nameserver)
		if err != nil {
			lastErr = err
			continue
		}
		if resp != nil && resp.Rcode == dns.RcodeSuccess {
			return nil
		}
		if resp != nil {
			lastErr = fmt.Errorf("rfc2136 update %s: %s", zone, dns.RcodeToString[resp.Rcode])
			continue
		}
		lastErr = fmt.Errorf("rfc2136 update %s: empty response", zone)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("rfc2136 update failed")
	}
	return lastErr
}

func (p *rfc2136Provider) zoneCandidates(domain, fqdn string) []string {
	seen := map[string]struct{}{}
	var zones []string
	add := func(value string) {
		value = dns.Fqdn(strings.ToLower(strings.TrimSpace(value)))
		if value == "." || value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		zones = append(zones, value)
	}
	add(p.zone)
	add(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "*."))
	name := dns.Fqdn(fqdn)
	for {
		add(name)
		parts := strings.SplitN(name, ".", 2)
		if len(parts) != 2 || parts[1] == "" || parts[1] == "." {
			break
		}
		name = parts[1]
	}
	return zones
}

func rfc2136Algorithm(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "hmac-sha1", dns.HmacSHA1:
		return dns.HmacSHA1
	case "hmac-sha512", dns.HmacSHA512:
		return dns.HmacSHA512
	default:
		return dns.HmacSHA256
	}
}
