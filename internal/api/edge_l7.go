package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

// Headers that let Angelos authenticate L7 pushes. The signature is
// HMAC-SHA256 keyed with the edge's own servers.token, so the token never
// travels on the wire and a captured request cannot be altered or replayed
// outside the allowed clock skew. See docs/ANGELOS_API.md.
const (
	edgeTimestampHeader = "X-Dorian-Timestamp"
	edgeSignatureHeader = "X-Dorian-Signature"
	edgeSignatureScheme = "v1="
	edgeSignatureMaxAge = 5 * time.Minute
	l7EdgeTimeout       = 60 * time.Second
)

var (
	l7EdgeMu     sync.RWMutex
	l7EdgeScheme = "http"
	l7EdgePort   = "5000"
	l7EdgeClient = &http.Client{Timeout: l7EdgeTimeout}
)

// configureL7Edge makes L7 pushes use the same AGENT_SCHEME / AGENT_PORT as L4.
func configureL7Edge(cfg config.Config) {
	l7EdgeMu.Lock()
	defer l7EdgeMu.Unlock()
	if scheme := strings.ToLower(strings.TrimSpace(cfg.AgentScheme)); scheme == "http" || scheme == "https" {
		l7EdgeScheme = scheme
	}
	if port := strings.TrimSpace(cfg.AgentPort); port != "" {
		l7EdgePort = port
	}
}

func l7EdgeURL(ip, apiPath string) string {
	l7EdgeMu.RLock()
	defer l7EdgeMu.RUnlock()
	return l7EdgeScheme + "://" + net.JoinHostPort(strings.TrimSpace(ip), l7EdgePort) + apiPath
}

// newL7EdgeRequest builds a signed POST to an edge's Angelos L7 API.
func newL7EdgeRequest(ctx context.Context, server store.ServerView, apiPath string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l7EdgeURL(server.IP, apiPath), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	signEdgeRequest(req, server.Token, body, time.Now())
	return req, nil
}

func edgeSignature(token, method, path, timestamp string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(strings.ToUpper(method) + "\n" + path + "\n" + timestamp + "\n" + hex.EncodeToString(bodyHash[:])))
	return edgeSignatureScheme + hex.EncodeToString(mac.Sum(nil))
}

func signEdgeRequest(req *http.Request, token string, body []byte, now time.Time) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	req.Header.Set(edgeTimestampHeader, timestamp)
	req.Header.Set(edgeSignatureHeader, edgeSignature(token, req.Method, req.URL.Path, timestamp, body))
}

// verifyEdgeSignature is the check Angelos must perform; kept here as the
// reference implementation and for tests.
// fetchEdgeL7Attack loads the live incident snapshot from Angelos
// (`GET /API/L7/l7_attack`). Used by the attack console so charts update while
// an incident is still active (timeline is present on the edge GET API).
func fetchEdgeL7Attack(ctx context.Context, server store.ServerView, reqID string) (store.L7AttackIncident, error) {
	reqID = strings.TrimSpace(reqID)
	if strings.TrimSpace(server.IP) == "" || strings.TrimSpace(server.Token) == "" || reqID == "" {
		return store.L7AttackIncident{}, errors.New("missing edge identity")
	}
	query := url.Values{}
	query.Set("id", reqID)
	query.Set("token", server.Token)
	endpoint := l7EdgeURL(server.IP, "/API/L7/l7_attack") + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return store.L7AttackIncident{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(server.Token))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return store.L7AttackIncident{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return store.L7AttackIncident{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return store.L7AttackIncident{}, fmt.Errorf("edge l7_attack status %d", resp.StatusCode)
	}
	var payload struct {
		Status string                 `json:"status"`
		Attack store.L7AttackIncident `json:"attack"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return store.L7AttackIncident{}, err
	}
	if strings.TrimSpace(payload.Attack.ID) == "" {
		payload.Attack.ID = reqID
	}
	return payload.Attack, nil
}

func verifyEdgeSignature(token, method, path string, header http.Header, body []byte, now time.Time) error {
	timestamp := strings.TrimSpace(header.Get(edgeTimestampHeader))
	signature := strings.TrimSpace(header.Get(edgeSignatureHeader))
	if timestamp == "" || signature == "" {
		return errors.New("missing signature headers")
	}
	unix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("invalid timestamp")
	}
	skew := now.Sub(time.Unix(unix, 0))
	if skew > edgeSignatureMaxAge || skew < -edgeSignatureMaxAge {
		return fmt.Errorf("timestamp outside allowed skew (%s)", skew.Round(time.Second))
	}
	expected := edgeSignature(strings.TrimSpace(token), method, path, timestamp, body)
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return errors.New("signature mismatch")
	}
	return nil
}
