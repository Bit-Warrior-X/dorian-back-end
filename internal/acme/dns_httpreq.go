package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/config"
)

type httpReqProvider struct {
	endpoint string
	username string
	password string
	client   *http.Client
}

type httpReqPayload struct {
	FQDN   string `json:"fqdn"`
	Value  string `json:"value"`
	Action string `json:"action"`
}

func newHTTPReqProvider(cfg config.Config) (*httpReqProvider, error) {
	endpoint := strings.TrimSpace(cfg.AcmeHTTPReqEndpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("httpreq endpoint is required")
	}
	return &httpReqProvider{
		endpoint: strings.TrimRight(endpoint, "/"),
		username: strings.TrimSpace(cfg.AcmeHTTPReqUsername),
		password: cfg.AcmeHTTPReqPassword,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}, nil
}

func (p *httpReqProvider) Present(ctx context.Context, _, fqdn, value string) error {
	return p.post(ctx, httpReqPayload{FQDN: fqdn, Value: value, Action: "present"})
}

func (p *httpReqProvider) CleanUp(ctx context.Context, _, fqdn, value string) error {
	return p.post(ctx, httpReqPayload{FQDN: fqdn, Value: value, Action: "cleanup"})
}

func (p *httpReqProvider) Resolver() string {
	return ""
}

func (p *httpReqProvider) post(ctx context.Context, payload httpReqPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.username != "" || p.password != "" {
		req.SetBasicAuth(p.username, p.password)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("httpreq %s: status %d %s", payload.Action, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}
