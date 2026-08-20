package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/config"
)

type cloudflareProvider struct {
	token    string
	zoneID   string
	recordID string
	name     string
	client   *http.Client
}

type cloudflareAPIResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func newCloudflareProvider(cfg config.Config) (*cloudflareProvider, error) {
	token := strings.TrimSpace(cfg.AcmeCloudflareAPIToken)
	zoneID := strings.TrimSpace(cfg.AcmeCloudflareZoneID)
	recordID := strings.TrimSpace(cfg.AcmeCloudflareRecordID)
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cfg.AcmeDNSAlias)), ".")
	if token == "" {
		return nil, fmt.Errorf("cloudflare API token is required")
	}
	if zoneID == "" || recordID == "" {
		return nil, fmt.Errorf("cloudflare zone ID and record ID are required")
	}
	if name == "" {
		name = "acme-validation.dorian.center"
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false, // HTTP/1.1 is more reliable on this host path
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	return &cloudflareProvider{
		token:    token,
		zoneID:   zoneID,
		recordID: recordID,
		name:     name,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}, nil
}

func (p *cloudflareProvider) Present(ctx context.Context, _, _, value string) error {
	return p.patchTXT(ctx, value)
}

func (p *cloudflareProvider) CleanUp(ctx context.Context, _, _, _ string) error {
	// Shared single TXT alias is reused by every site. Resetting it to "-" causes
	// the next issuance to race Let's Encrypt caches that still serve the old/dash
	// value. Leave the last challenge token in place; Present() overwrites it.
	return nil
}

func (p *cloudflareProvider) Resolver() string {
	return "1.1.1.1:53"
}

func (p *cloudflareProvider) patchTXT(ctx context.Context, value string) error {
	payload, err := json.Marshal(map[string]any{
		"type":    "TXT",
		"name":    p.name,
		"content": value,
		"ttl":     60,
	})
	if err != nil {
		return err
	}
	path := "/zones/" + p.zoneID + "/dns_records/" + p.recordID
	url := "https://api.cloudflare.com/client/v4" + path

	var lastErr error
	for attempt := 1; attempt <= 8; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := p.patchTXTOnce(ctx, url, path, payload)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isTransientNetErr(err) || attempt == 8 {
			break
		}
		backoff := time.Duration(attempt*attempt) * time.Second
		if backoff > 15*time.Second {
			backoff = 15 * time.Second
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return lastErr
}

func (p *cloudflareProvider) patchTXTOnce(ctx context.Context, url, path string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "close")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var parsed cloudflareAPIResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("cloudflare response: %w", err)
	}
	if resp.StatusCode >= 300 || !parsed.Success {
		message := strings.TrimSpace(string(raw))
		if len(parsed.Errors) > 0 && parsed.Errors[0].Message != "" {
			message = parsed.Errors[0].Message
		}
		if resp.StatusCode == http.StatusUnauthorized || strings.Contains(strings.ToLower(message), "invalid api token") {
			return fmt.Errorf("cloudflare API token is invalid or expired; update ACME_CLOUDFLARE_API_TOKEN in .env and restart the backend")
		}
		return fmt.Errorf("cloudflare PATCH %s: %s", path, message)
	}
	return nil
}

func isTransientNetErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"connection reset by peer",
		"i/o timeout",
		"tls handshake timeout",
		"eof",
		"broken pipe",
		"temporary failure",
		"server misbehaving",
		"connection refused",
		"network is unreachable",
		"http2: ",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	var netErr net.Error
	if ok := errorAsNet(err, &netErr); ok && netErr.Timeout() {
		return true
	}
	return false
}

func errorAsNet(err error, target *net.Error) bool {
	for err != nil {
		if ne, ok := err.(net.Error); ok {
			*target = ne
			return true
		}
		unwrap, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrap.Unwrap()
	}
	return false
}
