package api

import (
	"net"
	"net/http"
	"strings"
)

// clientIPFromRequest returns the caller's IP. Forwarding headers are honoured
// only when the direct peer is a local reverse proxy (nginx on this host);
// otherwise any client could spoof them to dodge per-IP limits or forge audit
// entries.
func clientIPFromRequest(r *http.Request) string {
	peer := remoteHost(r.RemoteAddr)
	if !isTrustedProxy(peer) {
		return peer
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" && net.ParseIP(realIP) != nil {
		return realIP
	}
	// The right-most X-Forwarded-For entry is the one appended by our proxy.
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		candidate := strings.TrimSpace(parts[len(parts)-1])
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	return peer
}

func remoteHost(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil && host != "" {
		return host
	}
	return remoteAddr
}

func isTrustedProxy(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
