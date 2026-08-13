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
	return &cloudflareProvider{
		token:    token,
		zoneID:   zoneID,
		recordID: recordID,
		name:     name,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}, nil
}

func (p *cloudflareProvider) Present(ctx context.Context, _, _, value string) error {
	return p.patchTXT(ctx, value)
}

func (p *cloudflareProvider) CleanUp(ctx context.Context, _, _, _ string) error {
	return p.patchTXT(ctx, "-")
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, "https://api.cloudflare.com/client/v4"+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
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
		return fmt.Errorf("cloudflare PATCH %s: %s", path, message)
	}
	return nil
}
