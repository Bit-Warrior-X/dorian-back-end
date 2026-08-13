package acme

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type internalDNS struct {
	listen  string
	mu      sync.RWMutex
	records map[string][]string
}

func newInternalDNS(listen string) *internalDNS {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return nil
	}
	return &internalDNS{
		listen:  listen,
		records: make(map[string][]string),
	}
}

func (d *internalDNS) Present(_ context.Context, _, fqdn, value string) error {
	name := dns.Fqdn(strings.ToLower(fqdn))
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, existing := range d.records[name] {
		if existing == value {
			return nil
		}
	}
	d.records[name] = append(d.records[name], value)
	return nil
}

func (d *internalDNS) CleanUp(_ context.Context, _, fqdn, value string) error {
	name := dns.Fqdn(strings.ToLower(fqdn))
	d.mu.Lock()
	defer d.mu.Unlock()
	existing := d.records[name]
	kept := make([]string, 0, len(existing))
	for _, item := range existing {
		if item != value {
			kept = append(kept, item)
		}
	}
	if len(kept) == 0 {
		delete(d.records, name)
		return nil
	}
	d.records[name] = kept
	return nil
}

func (d *internalDNS) Resolver() string {
	host, port, err := net.SplitHostPort(d.listen)
	if err != nil {
		return "127.0.0.1:53"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func (d *internalDNS) Start(ctx context.Context) {
	if d == nil {
		return
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", d.serveDNS)
	udp := &dns.Server{Addr: d.listen, Net: "udp", Handler: mux}
	tcp := &dns.Server{Addr: d.listen, Net: "tcp", Handler: mux}
	go func() {
		log.Printf("acme dns-01 listening on udp %s", d.listen)
		if err := udp.ListenAndServe(); err != nil {
			log.Printf("acme dns-01 udp server failed: %v", err)
		}
	}()
	go func() {
		log.Printf("acme dns-01 listening on tcp %s", d.listen)
		if err := tcp.ListenAndServe(); err != nil {
			log.Printf("acme dns-01 tcp server failed: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
	}()
}

func (d *internalDNS) serveDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	if len(r.Question) == 0 {
		_ = w.WriteMsg(msg)
		return
	}
	q := r.Question[0]
	name := dns.Fqdn(strings.ToLower(q.Name))
	if q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY {
		d.mu.RLock()
		values := append([]string(nil), d.records[name]...)
		d.mu.RUnlock()
		for _, value := range values {
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
				Txt: []string{value},
			})
		}
	}
	_ = w.WriteMsg(msg)
}
