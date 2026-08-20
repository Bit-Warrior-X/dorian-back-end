package worker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

// ipRequestStatsHTTPTimeout controls the timeout for each HTTP call to the
// metrics endpoint.
const ipRequestStatsHTTPTimeout = 5 * time.Second

type ipRequestStatsClientConfig struct {
	port                string
	timestampsPath      string
	ipBucketPath        string
	ispBucketPath       string
	countryBucketPath   string
	refererBucketPath   string
	urlBucketPath       string
	userAgentBucketPath string
	serverTrafficPath   string
	siteTrafficPath     string
	domainRequestPath   string
	interval            time.Duration
}

type ipRequestStatsEntry struct {
	SiteID       int64  `json:"site_id"`
	RequestCount int64  `json:"request_count"`
	IP           string `json:"ip"`
}

// ipRequestStatsList can decode either of these shapes:
//  1. [{"request_count":10,"ip":"127.0.0.1"}, ...]
//  2. {"127.0.0.1":{"request_count":10}, "192.168.0.1":{"request_count":5}}
//  3. {"127.0.0.1":10, "192.168.0.1":5}
type ipRequestStatsList []ipRequestStatsEntry

func (l *ipRequestStatsList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}

	switch data[0] {
	case '[':
		var arr []ipRequestStatsEntry
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*l = arr
		return nil
	case '{':
		// First, try object values with explicit request_count.
		var objWithStruct map[string]struct {
			RequestCount int64 `json:"request_count"`
		}
		if err := json.Unmarshal(data, &objWithStruct); err == nil {
			var out []ipRequestStatsEntry
			for ip, v := range objWithStruct {
				out = append(out, ipRequestStatsEntry{
					IP:           ip,
					RequestCount: v.RequestCount,
				})
			}
			*l = out
			return nil
		}

		// Fallback: object values are plain counts.
		var objWithInt map[string]int64
		if err := json.Unmarshal(data, &objWithInt); err == nil {
			var out []ipRequestStatsEntry
			for ip, count := range objWithInt {
				out = append(out, ipRequestStatsEntry{
					IP:           ip,
					RequestCount: count,
				})
			}
			*l = out
			return nil
		}
	}

	// Unsupported shape; ignore rather than failing hard.
	return nil
}

type ipRequestStatsBucketResponse struct {
	Timestamp      int64              `json:"timestamp"`
	IPRequestStats ipRequestStatsList `json:"ip_request_stats"`
}

type ispRequestStatsEntry struct {
	SiteID       int64  `json:"site_id"`
	RequestCount int64  `json:"request_count"`
	ISP          string `json:"isp"`
}

// ispRequestStatsList mirrors ipRequestStatsList but for ISP data:
//  1. [{"request_count":4,"isp":"-"}, ...]
//  2. {"Some ISP":{"request_count":4}, "Other ISP":{"request_count":5}}
//  3. {"Some ISP":4, "Other ISP":5}
type ispRequestStatsList []ispRequestStatsEntry

func (l *ispRequestStatsList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}

	switch data[0] {
	case '[':
		var arr []ispRequestStatsEntry
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*l = arr
		return nil
	case '{':
		var objWithStruct map[string]struct {
			RequestCount int64 `json:"request_count"`
		}
		if err := json.Unmarshal(data, &objWithStruct); err == nil {
			var out []ispRequestStatsEntry
			for isp, v := range objWithStruct {
				out = append(out, ispRequestStatsEntry{
					ISP:          isp,
					RequestCount: v.RequestCount,
				})
			}
			*l = out
			return nil
		}

		var objWithInt map[string]int64
		if err := json.Unmarshal(data, &objWithInt); err == nil {
			var out []ispRequestStatsEntry
			for isp, count := range objWithInt {
				out = append(out, ispRequestStatsEntry{
					ISP:          isp,
					RequestCount: count,
				})
			}
			*l = out
			return nil
		}
	}

	return nil
}

type ispRequestStatsBucketResponse struct {
	Timestamp       int64               `json:"timestamp"`
	ISPRequestStats ispRequestStatsList `json:"isp_request_stats"`
}

type countryRequestStatsEntry struct {
	SiteID       int64  `json:"site_id"`
	CountryISO   string `json:"country_iso"`
	RequestCount int64  `json:"request_count"`
	BlockCount   int64  `json:"block_count"`
}

// countryRequestStatsList mirrors ipRequestStatsList but for country data.
type countryRequestStatsList []countryRequestStatsEntry

func (l *countryRequestStatsList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}

	switch data[0] {
	case '[':
		var arr []countryRequestStatsEntry
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*l = arr
		return nil
	case '{':
		// Object with explicit fields.
		var objWithStruct map[string]struct {
			RequestCount int64 `json:"request_count"`
			BlockCount   int64 `json:"block_count"`
		}
		if err := json.Unmarshal(data, &objWithStruct); err == nil {
			var out []countryRequestStatsEntry
			for iso, v := range objWithStruct {
				out = append(out, countryRequestStatsEntry{
					CountryISO:   iso,
					RequestCount: v.RequestCount,
					BlockCount:   v.BlockCount,
				})
			}
			*l = out
			return nil
		}

		// Fallback: object values are plain request counts.
		var objWithInt map[string]int64
		if err := json.Unmarshal(data, &objWithInt); err == nil {
			var out []countryRequestStatsEntry
			for iso, count := range objWithInt {
				out = append(out, countryRequestStatsEntry{
					CountryISO:   iso,
					RequestCount: count,
					BlockCount:   0,
				})
			}
			*l = out
			return nil
		}
	}

	return nil
}

type countryRequestStatsBucketResponse struct {
	Timestamp           int64                   `json:"timestamp"`
	CountryRequestStats countryRequestStatsList `json:"country_request_stats"`
}

type refererRequestStatsEntry struct {
	SiteID       int64  `json:"site_id"`
	RequestCount int64  `json:"request_count"`
	Referer      string `json:"referer"`
}

// refererRequestStatsList mirrors ispRequestStatsList but for referer data.
// It supports:
//  1. [{"request_count":4,"referer":"-"}, ...]
//  2. {"https://example.com":{"request_count":4}, ...}
//  3. {"https://example.com":4, ...}
type refererRequestStatsList []refererRequestStatsEntry

func (l *refererRequestStatsList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}

	switch data[0] {
	case '[':
		var arr []refererRequestStatsEntry
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*l = arr
		return nil
	case '{':
		var objWithStruct map[string]struct {
			RequestCount int64 `json:"request_count"`
		}
		if err := json.Unmarshal(data, &objWithStruct); err == nil {
			var out []refererRequestStatsEntry
			for ref, v := range objWithStruct {
				out = append(out, refererRequestStatsEntry{
					Referer:      ref,
					RequestCount: v.RequestCount,
				})
			}
			*l = out
			return nil
		}

		var objWithInt map[string]int64
		if err := json.Unmarshal(data, &objWithInt); err == nil {
			var out []refererRequestStatsEntry
			for ref, count := range objWithInt {
				out = append(out, refererRequestStatsEntry{
					Referer:      ref,
					RequestCount: count,
				})
			}
			*l = out
			return nil
		}
	}

	return nil
}

type refererRequestStatsBucketResponse struct {
	Timestamp           int64                   `json:"timestamp"`
	RefererRequestStats refererRequestStatsList `json:"referer_request_stats"`
}

type urlRequestStatsEntry struct {
	SiteID       int64  `json:"site_id"`
	RequestCount int64  `json:"request_count"`
	URL          string `json:"url"`
}

// urlRequestStatsList mirrors refererRequestStatsList but for URL data.
// It supports:
//  1. [{"request_count":4,"url":"/index.html"}, ...]
//  2. {"/index.html":{"request_count":4}, ...}
//  3. {"/index.html":4, ...}
type urlRequestStatsList []urlRequestStatsEntry

func (l *urlRequestStatsList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}

	switch data[0] {
	case '[':
		var arr []urlRequestStatsEntry
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*l = arr
		return nil
	case '{':
		var objWithStruct map[string]struct {
			RequestCount int64 `json:"request_count"`
		}
		if err := json.Unmarshal(data, &objWithStruct); err == nil {
			var out []urlRequestStatsEntry
			for u, v := range objWithStruct {
				out = append(out, urlRequestStatsEntry{
					URL:          u,
					RequestCount: v.RequestCount,
				})
			}
			*l = out
			return nil
		}

		var objWithInt map[string]int64
		if err := json.Unmarshal(data, &objWithInt); err == nil {
			var out []urlRequestStatsEntry
			for u, count := range objWithInt {
				out = append(out, urlRequestStatsEntry{
					URL:          u,
					RequestCount: count,
				})
			}
			*l = out
			return nil
		}
	}

	return nil
}

type urlRequestStatsBucketResponse struct {
	Timestamp       int64               `json:"timestamp"`
	URLRequestStats urlRequestStatsList `json:"url_request_stats"`
}

type userAgentRequestStatsEntry struct {
	SiteID       int64 `json:"site_id"`
	RequestCount int64 `json:"request_count"`
	// Primary JSON field name; many exporters use "useragent".
	UserAgent string `json:"useragent"`
	// Alternate field for robustness.
	UserAgentAlt string `json:"user_agent"`
}

// userAgentRequestStatsList supports:
//  1. [{"request_count":4,"useragent":"Mozilla/5.0"}, ...]
//  2. [{"request_count":4,"user_agent":"Mozilla/5.0"}, ...]
//  3. {"Mozilla/5.0":{"request_count":4}, ...}
//  4. {"Mozilla/5.0":4, ...}
type userAgentRequestStatsList []userAgentRequestStatsEntry

func (l *userAgentRequestStatsList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}

	switch data[0] {
	case '[':
		var arr []userAgentRequestStatsEntry
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		// Normalize alternate field into primary.
		for i := range arr {
			if arr[i].UserAgent == "" {
				arr[i].UserAgent = arr[i].UserAgentAlt
			}
		}
		*l = arr
		return nil
	case '{':
		var objWithStruct map[string]struct {
			RequestCount int64 `json:"request_count"`
		}
		if err := json.Unmarshal(data, &objWithStruct); err == nil {
			var out []userAgentRequestStatsEntry
			for ua, v := range objWithStruct {
				out = append(out, userAgentRequestStatsEntry{
					UserAgent:    ua,
					RequestCount: v.RequestCount,
				})
			}
			*l = out
			return nil
		}

		var objWithInt map[string]int64
		if err := json.Unmarshal(data, &objWithInt); err == nil {
			var out []userAgentRequestStatsEntry
			for ua, count := range objWithInt {
				out = append(out, userAgentRequestStatsEntry{
					UserAgent:    ua,
					RequestCount: count,
				})
			}
			*l = out
			return nil
		}
	}

	return nil
}

type userAgentRequestStatsBucketResponse struct {
	Timestamp             int64                     `json:"timestamp"`
	UserAgentRequestStats userAgentRequestStatsList `json:"useragent_request_stats"`
}

type serverTrafficStatsPayload struct {
	Timestamp           int64   `json:"timestamp"`
	BandwidthL7Rx       float64 `json:"bandwidth_l7_rx"`
	BandwidthL7Tx       float64 `json:"bandwidth_l7_tx"`
	TrafficNicRx        float64 `json:"traffic_nic_rx"`
	TrafficNicTx        float64 `json:"traffic_nic_tx"`
	TrafficL7Rx         float64 `json:"traffic_l7_rx"`
	TrafficL7Tx         float64 `json:"traffic_l7_tx"`
	BandwidthNicRx      float64 `json:"bandwidth_nic_rx"`
	BandwidthNicTx      float64 `json:"bandwidth_nic_tx"`
	RequestCount        float64 `json:"request_count"`
	ResponseCount       float64 `json:"response_count"`
	BlockedRequestCount float64 `json:"blocked_request_count"`
	IPCount             float64 `json:"ip_count"`
	BlockedIPCount      float64 `json:"blocked_ip_count"`
	Code200             float64 `json:"code200"`
	Code206             float64 `json:"code206"`
	Code301             float64 `json:"code301"`
	Code302             float64 `json:"code302"`
	Code400             float64 `json:"code400"`
	Code403             float64 `json:"code403"`
	Code404             float64 `json:"code404"`
	Code444             float64 `json:"code444"`
	Code499             float64 `json:"code499"`
	Code500             float64 `json:"code500"`
	Code501             float64 `json:"code501"`
	Code502             float64 `json:"code502"`
	Code503             float64 `json:"code503"`
	Code504             float64 `json:"code504"`
	Code904             float64 `json:"code904"`
	Code929             float64 `json:"code929"`
	Code978             float64 `json:"code978"`
	GetCount            float64 `json:"get_count"`
	PostCount           float64 `json:"post_count"`
	DeleteCount         float64 `json:"delete_count"`
	PutCount            float64 `json:"put_count"`
	HeadCount           float64 `json:"head_count"`
	PatchCount          float64 `json:"patch_count"`
	OptionsCount        float64 `json:"options_count"`
	OthersCount         float64 `json:"others_count"`
	HTTP10Count         float64 `json:"http1_0_count"`
	HTTP11Count         float64 `json:"http1_1_count"`
	HTTP2Count          float64 `json:"http2_count"`
	HTTP3Count          float64 `json:"http3_count"`
}

// siteTrafficStatsEntry is per-site L7 aggregates (no NIC fields).
type siteTrafficStatsEntry struct {
	SiteID              int64   `json:"site_id"`
	TrafficL7Rx         float64 `json:"traffic_l7_rx"`
	TrafficL7Tx         float64 `json:"traffic_l7_tx"`
	BandwidthL7Rx       float64 `json:"bandwidth_l7_rx"`
	BandwidthL7Tx       float64 `json:"bandwidth_l7_tx"`
	RequestCount        float64 `json:"request_count"`
	ResponseCount       float64 `json:"response_count"`
	BlockedRequestCount float64 `json:"blocked_request_count"`
	IPCount             float64 `json:"ip_count"`
	BlockedIPCount      float64 `json:"blocked_ip_count"`
	Code200             float64 `json:"code200"`
	Code206             float64 `json:"code206"`
	Code301             float64 `json:"code301"`
	Code302             float64 `json:"code302"`
	Code400             float64 `json:"code400"`
	Code403             float64 `json:"code403"`
	Code404             float64 `json:"code404"`
	Code444             float64 `json:"code444"`
	Code499             float64 `json:"code499"`
	Code500             float64 `json:"code500"`
	Code501             float64 `json:"code501"`
	Code502             float64 `json:"code502"`
	Code503             float64 `json:"code503"`
	Code504             float64 `json:"code504"`
	Code904             float64 `json:"code904"`
	Code929             float64 `json:"code929"`
	Code978             float64 `json:"code978"`
	GetCount            float64 `json:"get_count"`
	PostCount           float64 `json:"post_count"`
	DeleteCount         float64 `json:"delete_count"`
	PutCount            float64 `json:"put_count"`
	HeadCount           float64 `json:"head_count"`
	PatchCount          float64 `json:"patch_count"`
	OptionsCount        float64 `json:"options_count"`
	OthersCount         float64 `json:"others_count"`
	HTTP10Count         float64 `json:"http1_0_count"`
	HTTP11Count         float64 `json:"http1_1_count"`
	HTTP2Count          float64 `json:"http2_count"`
	HTTP3Count          float64 `json:"http3_count"`
}

// siteTrafficStatsList accepts:
//  1. [{ "site_id": 12, ... }, ...]
//  2. { "12": { ...counters... }, "0": { ... } }  (Athens live shape)
type siteTrafficStatsList []siteTrafficStatsEntry

func (l *siteTrafficStatsList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	switch data[0] {
	case '[':
		var arr []siteTrafficStatsEntry
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*l = arr
		return nil
	case '{':
		var obj map[string]siteTrafficStatsEntry
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		out := make([]siteTrafficStatsEntry, 0, len(obj))
		for key, entry := range obj {
			if entry.SiteID == 0 {
				if id, err := strconv.ParseInt(strings.TrimSpace(key), 10, 64); err == nil {
					entry.SiteID = id
				}
			}
			out = append(out, entry)
		}
		*l = out
		return nil
	}
	return nil
}

type siteTrafficStatsBucketResponse struct {
	Timestamp        int64                `json:"timestamp"`
	SiteTrafficStats siteTrafficStatsList `json:"site_traffic_stats"`
}

type domainRequestStatsEntry struct {
	SiteID        int64   `json:"site_id"`
	Domain        string  `json:"domain"`
	RequestCount  int64   `json:"request_count"`
	TrafficL7Rx   float64 `json:"traffic_l7_rx"`
	TrafficL7Tx   float64 `json:"traffic_l7_tx"`
	BandwidthL7Rx float64 `json:"bandwidth_l7_rx"`
	BandwidthL7Tx float64 `json:"bandwidth_l7_tx"`
}

// domainRequestStatsList accepts:
//  1. [{ "site_id": 12, "domain": "www.example.com", ... }, ...]
//  2. { "www.example.com": { "site_id": 12, "request_count": N, ... }, ... }
type domainRequestStatsList []domainRequestStatsEntry

func (l *domainRequestStatsList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	switch data[0] {
	case '[':
		var arr []domainRequestStatsEntry
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*l = arr
		return nil
	case '{':
		var obj map[string]domainRequestStatsEntry
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		out := make([]domainRequestStatsEntry, 0, len(obj))
		for key, entry := range obj {
			if strings.TrimSpace(entry.Domain) == "" {
				entry.Domain = key
			}
			out = append(out, entry)
		}
		*l = out
		return nil
	}
	return nil
}

type domainRequestStatsBucketResponse struct {
	Timestamp          int64                  `json:"timestamp"`
	DomainRequestStats domainRequestStatsList `json:"domain_request_stats"`
}

// StartIPRequestStatsCollector launches a background goroutine that
// periodically polls the IP request statistics endpoint on each server and
// stores the results into the ip_request_stats table.
//
// The collector will run until the provided context is cancelled.
func StartIPRequestStatsCollector(ctx context.Context, cfg config.Config, dbConn *sql.DB, servers store.ServerStore) {
	if dbConn == nil || servers == nil {
		log.Printf("ip request stats collector disabled: missing dependencies")
		return
	}

	clientCfg := buildIPRequestStatsClientConfig(cfg)

	httpClient := &http.Client{
		Timeout: ipRequestStatsHTTPTimeout,
	}

	go func() {
		ticker := time.NewTicker(clientCfg.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if err := collectIPRequestStatsOnce(ctx, dbConn, servers, httpClient, clientCfg); err != nil {
				log.Printf("ip request stats collector error: %v", err)
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func collectIPRequestStatsOnce(ctx context.Context, dbConn *sql.DB, servers store.ServerStore, httpClient *http.Client, clientCfg ipRequestStatsClientConfig) error {
	serverViews, err := servers.ListWithUsers(ctx)
	if err != nil {
		return fmt.Errorf("list servers: %w", err)
	}

	for _, server := range serverViews {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		serverIP := strings.TrimSpace(server.IP)
		if serverIP == "" {
			continue
		}

		// Load the latest bucket we already have for this server so that we
		// only insert new buckets.
		latestBucket, ok, err := latestIPRequestBucketForServer(ctx, dbConn, server.ID)
		if err != nil {
			log.Printf("ip request stats collector: load latest bucket for server %d (%s): %v", server.ID, serverIP, err)
			continue
		}

		timestamps, err := fetchIPRequestTimestamps(ctx, httpClient, serverIP, clientCfg)
		if err != nil {
			log.Printf("ip request stats collector: fetch timestamps for server %d (%s): %v", server.ID, serverIP, err)
			continue
		}
		if len(timestamps) == 0 {
			continue
		}

		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i].Before(timestamps[j]) })

		for _, ts := range timestamps {
			if ok && !ts.After(latestBucket) {
				continue
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			respIP, err := fetchIPRequestBucket(ctx, httpClient, serverIP, ts.Unix(), clientCfg)
			if err != nil {
				log.Printf("ip request stats collector: fetch IP bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
			} else if len(respIP.IPRequestStats) > 0 {
				if err := insertIPRequestBucket(ctx, dbConn, server.ID, ts, respIP); err != nil {
					log.Printf("ip request stats collector: insert IP bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
				}
			}

			respISP, err := fetchISPRequestBucket(ctx, httpClient, serverIP, ts.Unix(), clientCfg)
			if err != nil {
				log.Printf("ip request stats collector: fetch ISP bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
			} else if len(respISP.ISPRequestStats) > 0 {
				if err := insertISPRequestBucket(ctx, dbConn, server.ID, ts, respISP); err != nil {
					log.Printf("ip request stats collector: insert ISP bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
				}
			}

			respCountry, err := fetchCountryRequestBucket(ctx, httpClient, serverIP, ts.Unix(), clientCfg)
			if err != nil {
				log.Printf("ip request stats collector: fetch Country bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
			} else if len(respCountry.CountryRequestStats) > 0 {
				if err := insertCountryRequestBucket(ctx, dbConn, server.ID, ts, respCountry); err != nil {
					log.Printf("ip request stats collector: insert Country bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
				}
			}

			respReferer, err := fetchRefererRequestBucket(ctx, httpClient, serverIP, ts.Unix(), clientCfg)
			if err != nil {
				log.Printf("ip request stats collector: fetch Referer bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
			} else if len(respReferer.RefererRequestStats) > 0 {
				if err := insertRefererRequestBucket(ctx, dbConn, server.ID, ts, respReferer); err != nil {
					log.Printf("ip request stats collector: insert Referer bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
				}
			}

			respURL, err := fetchURLRequestBucket(ctx, httpClient, serverIP, ts.Unix(), clientCfg)
			if err != nil {
				log.Printf("ip request stats collector: fetch URL bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
			} else if len(respURL.URLRequestStats) > 0 {
				if err := insertURLRequestBucket(ctx, dbConn, server.ID, ts, respURL); err != nil {
					log.Printf("ip request stats collector: insert URL bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
				}
			}

			respUA, err := fetchUserAgentRequestBucket(ctx, httpClient, serverIP, ts.Unix(), clientCfg)
			if err != nil {
				log.Printf("ip request stats collector: fetch UserAgent bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
			} else if len(respUA.UserAgentRequestStats) > 0 {
				if err := insertUserAgentRequestBucket(ctx, dbConn, server.ID, ts, respUA); err != nil {
					log.Printf("ip request stats collector: insert UserAgent bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
				}
			}

			respSite, err := fetchSiteTrafficBucket(ctx, httpClient, serverIP, ts.Unix(), clientCfg)
			if err != nil {
				log.Printf("ip request stats collector: fetch site traffic bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
			} else if len(respSite.SiteTrafficStats) > 0 {
				if err := insertSiteTrafficBucket(ctx, dbConn, server.ID, ts, respSite); err != nil {
					log.Printf("ip request stats collector: insert site traffic bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
				}
			}

			respDomain, err := fetchDomainRequestBucket(ctx, httpClient, serverIP, ts.Unix(), clientCfg)
			if err != nil {
				log.Printf("ip request stats collector: fetch domain request bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
			} else if len(respDomain.DomainRequestStats) > 0 {
				if err := insertDomainRequestBucket(ctx, dbConn, server.ID, ts, respDomain); err != nil {
					log.Printf("ip request stats collector: insert domain request bucket %d for server %d (%s): %v", ts.Unix(), server.ID, serverIP, err)
				}
			}

		}

		// After processing per-timestamp metrics, fetch the aggregated
		// server traffic snapshot and L4 attack stats for this server.
		if err := collectServerTrafficSnapshot(ctx, dbConn, httpClient, clientCfg, server.ID, serverIP); err != nil {
			log.Printf("ip request stats collector: collect server traffic snapshot for server %d (%s): %v", server.ID, serverIP, err)
		}
		if err := collectL4AttackStatsForServer(ctx, dbConn, httpClient, clientCfg.port, server.ID, serverIP); err != nil {
			log.Printf("ip request stats collector: collect l4 attack stats for server %d (%s): %v", server.ID, serverIP, err)
		}
	}

	return nil
}

// latestIPRequestBucketForServer returns the latest bucket_ts value for the
// given server ID, if any.
func latestIPRequestBucketForServer(ctx context.Context, dbConn *sql.DB, serverID int64) (time.Time, bool, error) {
	var latest sql.NullTime
	row := dbConn.QueryRowContext(ctx, `
		SELECT MAX(bucket_ts)
		FROM ip_request_stats
		WHERE server_id = ?`,
		serverID,
	)
	if err := row.Scan(&latest); err != nil {
		if err == sql.ErrNoRows {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, err
	}
	if !latest.Valid {
		return time.Time{}, false, nil
	}
	return latest.Time, true, nil
}

func fetchIPRequestTimestamps(ctx context.Context, httpClient *http.Client, serverIP string, clientCfg ipRequestStatsClientConfig) ([]time.Time, error) {
	targetHost := net.JoinHostPort(serverIP, clientCfg.port)
	url := "http://" + targetHost + clientCfg.timestampsPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build timestamps request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("timestamps request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("timestamps request returned status %d", resp.StatusCode)
	}

	// The endpoint may return:
	//  1. A bare JSON array: [1772460720, "1772460780", ...]
	//  2. An object with a "timestamps" array field.
	//  3. An object whose keys are timestamps.
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode timestamps response: %w", err)
	}

	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, nil
	}

	var out []time.Time

	switch raw[0] {
	case '[':
		var arr []interface{}
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, fmt.Errorf("decode timestamps array: %w", err)
		}
		out = append(out, parseTimestampInterfaces(arr)...)
	case '{':
		// First, try object with explicit "timestamps" field.
		var withField struct {
			Timestamps []interface{} `json:"timestamps"`
		}
		if err := json.Unmarshal(raw, &withField); err == nil && len(withField.Timestamps) > 0 {
			out = append(out, parseTimestampInterfaces(withField.Timestamps)...)
		} else {
			// Fallback: treat keys as timestamps.
			var obj map[string]interface{}
			if err := json.Unmarshal(raw, &obj); err == nil {
				for key := range obj {
					key = strings.TrimSpace(key)
					if key == "" {
						continue
					}
					tsInt, err := strconv.ParseInt(key, 10, 64)
					if err != nil || tsInt <= 0 {
						continue
					}
					out = append(out, time.Unix(tsInt, 0).UTC())
				}
				// Ensure stable order.
				sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
			}
		}
	default:
		// Unsupported top-level shape; ignore gracefully.
	}

	return out, nil
}

func parseTimestampInterfaces(items []interface{}) []time.Time {
	var out []time.Time
	for _, item := range items {
		var tsInt int64
		switch v := item.(type) {
		case float64:
			tsInt = int64(v)
		case string:
			parsed, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				continue
			}
			tsInt = parsed
		default:
			continue
		}
		if tsInt <= 0 {
			continue
		}
		out = append(out, time.Unix(tsInt, 0).UTC())
	}
	return out
}

type l4AttackStatsInner struct {
	UDP   int64 `json:"udp"`
	GRE   int64 `json:"gre"`
	Other int64 `json:"other"`
	Total int64 `json:"total"`
	Allow int64 `json:"allow"`
	Block int64 `json:"block"`
	Syn   int64 `json:"syn"`
	Ack   int64 `json:"ack"`
	ICMP  int64 `json:"icmp"`
	TCP   int64 `json:"tcp"`
	Rst   int64 `json:"rst"`
}

type l4AttackStatsBucketResponse struct {
	Timestamp int64              `json:"timestamp"`
	Stats     l4AttackStatsInner `json:"stats"`
}

func collectL4AttackStatsForServer(
	ctx context.Context,
	dbConn *sql.DB,
	httpClient *http.Client,
	port string,
	serverID int64,
	serverIP string,
) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return nil
	}

	latest, ok, err := latestL4AttackBucketForServer(ctx, dbConn, serverID)
	if err != nil {
		return fmt.Errorf("load latest l4 attack bucket: %w", err)
	}

	timestamps, err := fetchL4AttackTimestamps(ctx, httpClient, serverIP, port)
	if err != nil {
		return fmt.Errorf("fetch l4 attack timestamps: %w", err)
	}
	if len(timestamps) == 0 {
		return nil
	}

	sort.Slice(timestamps, func(i, j int) bool { return timestamps[i].Before(timestamps[j]) })

	for _, ts := range timestamps {
		if ok && !ts.After(latest) {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		resp, err := fetchL4AttackBucket(ctx, httpClient, serverIP, port, ts.Unix())
		if err != nil {
			log.Printf("l4 attack stats collector: fetch bucket %d for server %d (%s): %v", ts.Unix(), serverID, serverIP, err)
			continue
		}

		if err := insertL4AttackBucket(ctx, dbConn, serverID, ts, resp); err != nil {
			log.Printf("l4 attack stats collector: insert bucket %d for server %d (%s): %v", ts.Unix(), serverID, serverIP, err)
			continue
		}
	}

	return nil
}

func latestL4AttackBucketForServer(ctx context.Context, dbConn *sql.DB, serverID int64) (time.Time, bool, error) {
	var latest sql.NullTime
	row := dbConn.QueryRowContext(ctx, `
		SELECT MAX(bucket_ts)
		FROM l4_attack_stats
		WHERE server_id = ?`,
		serverID,
	)
	if err := row.Scan(&latest); err != nil {
		if err == sql.ErrNoRows {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, err
	}
	if !latest.Valid {
		return time.Time{}, false, nil
	}
	return latest.Time, true, nil
}

func fetchL4AttackTimestamps(ctx context.Context, httpClient *http.Client, serverIP string, port string) ([]time.Time, error) {
	targetHost := net.JoinHostPort(serverIP, port)
	url := "http://" + targetHost + "/l4_attack_stats/timestamps"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build l4 timestamps request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("l4 timestamps request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("l4 timestamps request returned status %d", resp.StatusCode)
	}

	var arr []interface{}
	if err := json.NewDecoder(resp.Body).Decode(&arr); err != nil {
		return nil, fmt.Errorf("decode l4 timestamps response: %w", err)
	}

	return parseTimestampInterfaces(arr), nil
}

func fetchL4AttackBucket(
	ctx context.Context,
	httpClient *http.Client,
	serverIP string,
	port string,
	timestamp int64,
) (l4AttackStatsBucketResponse, error) {
	targetHost := net.JoinHostPort(serverIP, port)
	url := fmt.Sprintf("http://%s/l4_attack_stats?timestamp=%d", targetHost, timestamp)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return l4AttackStatsBucketResponse{}, fmt.Errorf("build l4 bucket request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return l4AttackStatsBucketResponse{}, fmt.Errorf("l4 bucket request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return l4AttackStatsBucketResponse{}, fmt.Errorf("l4 bucket request returned status %d", resp.StatusCode)
	}

	var parsed l4AttackStatsBucketResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return l4AttackStatsBucketResponse{}, fmt.Errorf("decode l4 bucket response: %w", err)
	}

	return parsed, nil
}

func insertL4AttackBucket(
	ctx context.Context,
	dbConn *sql.DB,
	serverID int64,
	bucket time.Time,
	data l4AttackStatsBucketResponse,
) error {
	_, err := dbConn.ExecContext(
		ctx,
		`
		INSERT INTO l4_attack_stats (
			server_id,
			bucket_ts,
			total_traffic,
			allowed_traffic,
			blocked_traffic,
			tcp,
			udp,
			icmp,
			gre,
			other,
			tcp_syn,
			tcp_ack,
			tcp_rst
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		)
		ON DUPLICATE KEY UPDATE
			total_traffic = VALUES(total_traffic),
			allowed_traffic = VALUES(allowed_traffic),
			blocked_traffic = VALUES(blocked_traffic),
			tcp = VALUES(tcp),
			udp = VALUES(udp),
			icmp = VALUES(icmp),
			gre = VALUES(gre),
			other = VALUES(other),
			tcp_syn = VALUES(tcp_syn),
			tcp_ack = VALUES(tcp_ack),
			tcp_rst = VALUES(tcp_rst)
		`,
		serverID,
		bucket,
		data.Stats.Total,
		data.Stats.Allow,
		data.Stats.Block,
		data.Stats.TCP,
		data.Stats.UDP,
		data.Stats.ICMP,
		data.Stats.GRE,
		data.Stats.Other,
		data.Stats.Syn,
		data.Stats.Ack,
		data.Stats.Rst,
	)
	if err != nil {
		return fmt.Errorf("insert l4_attack_stats: %w", err)
	}
	return nil
}

func fetchIPRequestBucket(ctx context.Context, httpClient *http.Client, serverIP string, timestamp int64, clientCfg ipRequestStatsClientConfig) (ipRequestStatsBucketResponse, error) {
	targetHost := net.JoinHostPort(serverIP, clientCfg.port)

	url := fmt.Sprintf("http://%s%s?timestamp=%d", targetHost, clientCfg.ipBucketPath, timestamp)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ipRequestStatsBucketResponse{}, fmt.Errorf("build bucket request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return ipRequestStatsBucketResponse{}, fmt.Errorf("bucket request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return ipRequestStatsBucketResponse{}, fmt.Errorf("bucket request returned status %d", resp.StatusCode)
	}

	var parsed ipRequestStatsBucketResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return ipRequestStatsBucketResponse{}, fmt.Errorf("decode bucket response: %w", err)
	}

	// If the response timestamp is present and differs from the requested
	// timestamp, we still trust the server's value but log a warning.
	if parsed.Timestamp != 0 && parsed.Timestamp != timestamp {
		log.Printf("ip request stats collector: bucket timestamp mismatch, requested %d got %d", timestamp, parsed.Timestamp)
	}

	return parsed, nil
}

func fetchISPRequestBucket(ctx context.Context, httpClient *http.Client, serverIP string, timestamp int64, clientCfg ipRequestStatsClientConfig) (ispRequestStatsBucketResponse, error) {
	targetHost := net.JoinHostPort(serverIP, clientCfg.port)

	url := fmt.Sprintf("http://%s%s?timestamp=%d", targetHost, clientCfg.ispBucketPath, timestamp)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ispRequestStatsBucketResponse{}, fmt.Errorf("build ISP bucket request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return ispRequestStatsBucketResponse{}, fmt.Errorf("ISP bucket request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return ispRequestStatsBucketResponse{}, fmt.Errorf("ISP bucket request returned status %d", resp.StatusCode)
	}

	var parsed ispRequestStatsBucketResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return ispRequestStatsBucketResponse{}, fmt.Errorf("decode ISP bucket response: %w", err)
	}

	if parsed.Timestamp != 0 && parsed.Timestamp != timestamp {
		log.Printf("ip request stats collector: ISP bucket timestamp mismatch, requested %d got %d", timestamp, parsed.Timestamp)
	}

	return parsed, nil
}

func fetchCountryRequestBucket(ctx context.Context, httpClient *http.Client, serverIP string, timestamp int64, clientCfg ipRequestStatsClientConfig) (countryRequestStatsBucketResponse, error) {
	targetHost := net.JoinHostPort(serverIP, clientCfg.port)

	url := fmt.Sprintf("http://%s%s?timestamp=%d", targetHost, clientCfg.countryBucketPath, timestamp)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return countryRequestStatsBucketResponse{}, fmt.Errorf("build Country bucket request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return countryRequestStatsBucketResponse{}, fmt.Errorf("Country bucket request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return countryRequestStatsBucketResponse{}, fmt.Errorf("Country bucket request returned status %d", resp.StatusCode)
	}

	var parsed countryRequestStatsBucketResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return countryRequestStatsBucketResponse{}, fmt.Errorf("decode Country bucket response: %w", err)
	}

	if parsed.Timestamp != 0 && parsed.Timestamp != timestamp {
		log.Printf("ip request stats collector: Country bucket timestamp mismatch, requested %d got %d", timestamp, parsed.Timestamp)
	}

	return parsed, nil
}

func fetchRefererRequestBucket(ctx context.Context, httpClient *http.Client, serverIP string, timestamp int64, clientCfg ipRequestStatsClientConfig) (refererRequestStatsBucketResponse, error) {
	targetHost := net.JoinHostPort(serverIP, clientCfg.port)

	// Referer endpoint follows the same style as other stats endpoints that
	// embed the timestamp in the path, e.g. /referer_request_stats/1772460720.
	url := fmt.Sprintf("http://%s%s?timestamp=%d", targetHost, clientCfg.refererBucketPath, timestamp)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return refererRequestStatsBucketResponse{}, fmt.Errorf("build Referer bucket request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return refererRequestStatsBucketResponse{}, fmt.Errorf("Referer bucket request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return refererRequestStatsBucketResponse{}, fmt.Errorf("Referer bucket request returned status %d", resp.StatusCode)
	}

	var parsed refererRequestStatsBucketResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return refererRequestStatsBucketResponse{}, fmt.Errorf("decode Referer bucket response: %w", err)
	}

	if parsed.Timestamp != 0 && parsed.Timestamp != timestamp {
		log.Printf("ip request stats collector: Referer bucket timestamp mismatch, requested %d got %d", timestamp, parsed.Timestamp)
	}

	return parsed, nil
}

func fetchURLRequestBucket(ctx context.Context, httpClient *http.Client, serverIP string, timestamp int64, clientCfg ipRequestStatsClientConfig) (urlRequestStatsBucketResponse, error) {
	targetHost := net.JoinHostPort(serverIP, clientCfg.port)

	url := fmt.Sprintf("http://%s%s?timestamp=%d", targetHost, clientCfg.urlBucketPath, timestamp)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return urlRequestStatsBucketResponse{}, fmt.Errorf("build URL bucket request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return urlRequestStatsBucketResponse{}, fmt.Errorf("URL bucket request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return urlRequestStatsBucketResponse{}, fmt.Errorf("URL bucket request returned status %d", resp.StatusCode)
	}

	var parsed urlRequestStatsBucketResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return urlRequestStatsBucketResponse{}, fmt.Errorf("decode URL bucket response: %w", err)
	}

	if parsed.Timestamp != 0 && parsed.Timestamp != timestamp {
		log.Printf("ip request stats collector: URL bucket timestamp mismatch, requested %d got %d", timestamp, parsed.Timestamp)
	}

	return parsed, nil
}

func fetchUserAgentRequestBucket(ctx context.Context, httpClient *http.Client, serverIP string, timestamp int64, clientCfg ipRequestStatsClientConfig) (userAgentRequestStatsBucketResponse, error) {
	targetHost := net.JoinHostPort(serverIP, clientCfg.port)

	url := fmt.Sprintf("http://%s%s?timestamp=%d", targetHost, clientCfg.userAgentBucketPath, timestamp)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return userAgentRequestStatsBucketResponse{}, fmt.Errorf("build UserAgent bucket request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return userAgentRequestStatsBucketResponse{}, fmt.Errorf("UserAgent bucket request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return userAgentRequestStatsBucketResponse{}, fmt.Errorf("UserAgent bucket request returned status %d", resp.StatusCode)
	}

	var parsed userAgentRequestStatsBucketResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return userAgentRequestStatsBucketResponse{}, fmt.Errorf("decode UserAgent bucket response: %w", err)
	}

	if parsed.Timestamp != 0 && parsed.Timestamp != timestamp {
		log.Printf("ip request stats collector: UserAgent bucket timestamp mismatch, requested %d got %d", timestamp, parsed.Timestamp)
	}

	return parsed, nil
}

func fetchSiteTrafficBucket(ctx context.Context, httpClient *http.Client, serverIP string, timestamp int64, clientCfg ipRequestStatsClientConfig) (siteTrafficStatsBucketResponse, error) {
	targetHost := net.JoinHostPort(serverIP, clientCfg.port)

	url := fmt.Sprintf("http://%s%s?timestamp=%d", targetHost, clientCfg.siteTrafficPath, timestamp)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return siteTrafficStatsBucketResponse{}, fmt.Errorf("build site traffic bucket request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return siteTrafficStatsBucketResponse{}, fmt.Errorf("site traffic bucket request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return siteTrafficStatsBucketResponse{}, fmt.Errorf("site traffic bucket request returned status %d", resp.StatusCode)
	}

	var parsed siteTrafficStatsBucketResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return siteTrafficStatsBucketResponse{}, fmt.Errorf("decode site traffic bucket response: %w", err)
	}

	if parsed.Timestamp != 0 && parsed.Timestamp != timestamp {
		log.Printf("ip request stats collector: site traffic bucket timestamp mismatch, requested %d got %d", timestamp, parsed.Timestamp)
	}

	return parsed, nil
}

func fetchDomainRequestBucket(ctx context.Context, httpClient *http.Client, serverIP string, timestamp int64, clientCfg ipRequestStatsClientConfig) (domainRequestStatsBucketResponse, error) {
	targetHost := net.JoinHostPort(serverIP, clientCfg.port)

	url := fmt.Sprintf("http://%s%s?timestamp=%d", targetHost, clientCfg.domainRequestPath, timestamp)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domainRequestStatsBucketResponse{}, fmt.Errorf("build domain request bucket request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return domainRequestStatsBucketResponse{}, fmt.Errorf("domain request bucket request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return domainRequestStatsBucketResponse{}, fmt.Errorf("domain request bucket request returned status %d", resp.StatusCode)
	}

	var parsed domainRequestStatsBucketResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return domainRequestStatsBucketResponse{}, fmt.Errorf("decode domain request bucket response: %w", err)
	}

	if parsed.Timestamp != 0 && parsed.Timestamp != timestamp {
		log.Printf("ip request stats collector: domain request bucket timestamp mismatch, requested %d got %d", timestamp, parsed.Timestamp)
	}

	return parsed, nil
}

func collectServerTrafficSnapshot(ctx context.Context, dbConn *sql.DB, httpClient *http.Client, clientCfg ipRequestStatsClientConfig, serverID int64, serverIP string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return nil
	}

	targetHost := net.JoinHostPort(serverIP, clientCfg.port)
	url := "http://" + targetHost + clientCfg.serverTrafficPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build server traffic request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("server traffic request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("server traffic request returned status %d", resp.StatusCode)
	}

	var payload serverTrafficStatsPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("decode server traffic response: %w", err)
	}

	// Use the timestamp from the payload when available; otherwise fall back
	// to the current collection time.
	var bucket time.Time
	if payload.Timestamp > 0 {
		bucket = time.Unix(payload.Timestamp, 0).UTC()
	} else {
		bucket = time.Now().UTC()
	}
	return insertServerTrafficSnapshot(ctx, dbConn, serverID, bucket, payload)
}

func insertIPRequestBucket(ctx context.Context, dbConn *sql.DB, serverID int64, bucket time.Time, data ipRequestStatsBucketResponse) error {
	if len(data.IPRequestStats) == 0 {
		return nil
	}

	valuePlaceholders := make([]string, 0, len(data.IPRequestStats))
	args := make([]any, 0, len(data.IPRequestStats)*5)

	for _, row := range data.IPRequestStats {
		ip := strings.TrimSpace(row.IP)
		if ip == "" || row.RequestCount <= 0 {
			continue
		}
		valuePlaceholders = append(valuePlaceholders, "(?, ?, ?, INET6_ATON(?), ?)")
		args = append(args, serverID, row.SiteID, bucket, ip, row.RequestCount)
	}

	if len(valuePlaceholders) == 0 {
		return nil
	}

	query := `
		INSERT INTO ip_request_stats (server_id, site_id, bucket_ts, ip, request_count)
		VALUES ` + strings.Join(valuePlaceholders, ",") + `
		ON DUPLICATE KEY UPDATE
			request_count = VALUES(request_count)`

	_, err := dbConn.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("insert ip_request_stats: %w", err)
	}
	return nil
}

func insertISPRequestBucket(ctx context.Context, dbConn *sql.DB, serverID int64, bucket time.Time, data ispRequestStatsBucketResponse) error {
	if len(data.ISPRequestStats) == 0 {
		return nil
	}

	valuePlaceholders := make([]string, 0, len(data.ISPRequestStats))
	args := make([]any, 0, len(data.ISPRequestStats)*6)

	for _, row := range data.ISPRequestStats {
		isp := strings.TrimSpace(row.ISP)
		if isp == "" || row.RequestCount <= 0 {
			continue
		}
		// isp_hash is derived from request_isp using CRC32 to match schema.
		valuePlaceholders = append(valuePlaceholders, "(?, ?, ?, ?, CRC32(?), ?)")
		args = append(args, serverID, row.SiteID, bucket, isp, isp, row.RequestCount)
	}

	if len(valuePlaceholders) == 0 {
		return nil
	}

	query := `
		INSERT INTO isp_request_stats (server_id, site_id, bucket_ts, request_isp, isp_hash, request_count)
		VALUES ` + strings.Join(valuePlaceholders, ",") + `
		ON DUPLICATE KEY UPDATE
			request_count = VALUES(request_count)`

	_, err := dbConn.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("insert isp_request_stats: %w", err)
	}
	return nil
}

func insertCountryRequestBucket(ctx context.Context, dbConn *sql.DB, serverID int64, bucket time.Time, data countryRequestStatsBucketResponse) error {
	if len(data.CountryRequestStats) == 0 {
		return nil
	}

	valuePlaceholders := make([]string, 0, len(data.CountryRequestStats))
	args := make([]any, 0, len(data.CountryRequestStats)*6)

	for _, row := range data.CountryRequestStats {
		country := strings.TrimSpace(row.CountryISO)
		if country == "" {
			continue
		}
		if row.RequestCount <= 0 && row.BlockCount <= 0 {
			continue
		}
		valuePlaceholders = append(valuePlaceholders, "(?, ?, ?, ?, ?, ?)")
		args = append(args, serverID, row.SiteID, bucket, country, row.RequestCount, row.BlockCount)
	}

	if len(valuePlaceholders) == 0 {
		return nil
	}

	query := `
		INSERT INTO country_request_stats (server_id, site_id, bucket_ts, country_code, request_count, blocked_request_count)
		VALUES ` + strings.Join(valuePlaceholders, ",") + `
		ON DUPLICATE KEY UPDATE
			request_count = VALUES(request_count),
			blocked_request_count = VALUES(blocked_request_count)`

	_, err := dbConn.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("insert country_request_stats: %w", err)
	}
	return nil
}

func insertRefererRequestBucket(ctx context.Context, dbConn *sql.DB, serverID int64, bucket time.Time, data refererRequestStatsBucketResponse) error {
	if len(data.RefererRequestStats) == 0 {
		return nil
	}

	valuePlaceholders := make([]string, 0, len(data.RefererRequestStats))
	args := make([]any, 0, len(data.RefererRequestStats)*6)

	for _, row := range data.RefererRequestStats {
		ref := strings.TrimSpace(row.Referer)
		if ref == "" || row.RequestCount <= 0 {
			continue
		}
		// referer_hash is derived from request_referer using CRC32.
		valuePlaceholders = append(valuePlaceholders, "(?, ?, ?, ?, CRC32(?), ?)")
		args = append(args, serverID, row.SiteID, bucket, ref, ref, row.RequestCount)
	}

	if len(valuePlaceholders) == 0 {
		return nil
	}

	query := `
		INSERT INTO referer_request_stats (server_id, site_id, bucket_ts, request_referer, referer_hash, request_count)
		VALUES ` + strings.Join(valuePlaceholders, ",") + `
		ON DUPLICATE KEY UPDATE
			request_count = VALUES(request_count)`

	_, err := dbConn.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("insert referer_request_stats: %w", err)
	}
	return nil
}

func insertURLRequestBucket(ctx context.Context, dbConn *sql.DB, serverID int64, bucket time.Time, data urlRequestStatsBucketResponse) error {
	if len(data.URLRequestStats) == 0 {
		return nil
	}

	valuePlaceholders := make([]string, 0, len(data.URLRequestStats))
	args := make([]any, 0, len(data.URLRequestStats)*6)

	for _, row := range data.URLRequestStats {
		url := strings.TrimSpace(row.URL)
		if url == "" || row.RequestCount <= 0 {
			continue
		}
		// url_hash is derived from request_url using CRC32.
		valuePlaceholders = append(valuePlaceholders, "(?, ?, ?, ?, CRC32(?), ?)")
		args = append(args, serverID, row.SiteID, bucket, url, url, row.RequestCount)
	}

	if len(valuePlaceholders) == 0 {
		return nil
	}

	query := `
		INSERT INTO url_request_stats (server_id, site_id, bucket_ts, request_url, url_hash, request_count)
		VALUES ` + strings.Join(valuePlaceholders, ",") + `
		ON DUPLICATE KEY UPDATE
			request_count = VALUES(request_count)`

	_, err := dbConn.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("insert url_request_stats: %w", err)
	}
	return nil
}

func insertUserAgentRequestBucket(ctx context.Context, dbConn *sql.DB, serverID int64, bucket time.Time, data userAgentRequestStatsBucketResponse) error {
	if len(data.UserAgentRequestStats) == 0 {
		return nil
	}

	valuePlaceholders := make([]string, 0, len(data.UserAgentRequestStats))
	args := make([]any, 0, len(data.UserAgentRequestStats)*6)

	for _, row := range data.UserAgentRequestStats {
		ua := strings.TrimSpace(row.UserAgent)
		if ua == "" || row.RequestCount <= 0 {
			continue
		}
		// useragent_hash is derived from request_useragent using CRC32.
		valuePlaceholders = append(valuePlaceholders, "(?, ?, ?, ?, CRC32(?), ?)")
		args = append(args, serverID, row.SiteID, bucket, ua, ua, row.RequestCount)
	}

	if len(valuePlaceholders) == 0 {
		return nil
	}

	query := `
		INSERT INTO useragent_request_stats (server_id, site_id, bucket_ts, request_useragent, useragent_hash, request_count)
		VALUES ` + strings.Join(valuePlaceholders, ",") + `
		ON DUPLICATE KEY UPDATE
			request_count = VALUES(request_count)`

	_, err := dbConn.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("insert useragent_request_stats: %w", err)
	}
	return nil
}

func insertSiteTrafficBucket(ctx context.Context, dbConn *sql.DB, serverID int64, bucket time.Time, data siteTrafficStatsBucketResponse) error {
	if len(data.SiteTrafficStats) == 0 {
		return nil
	}

	valuePlaceholders := make([]string, 0, len(data.SiteTrafficStats))
	args := make([]any, 0, len(data.SiteTrafficStats)*42)

	for _, p := range data.SiteTrafficStats {
		valuePlaceholders = append(valuePlaceholders, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		args = append(args,
			serverID,
			p.SiteID,
			bucket,
			p.TrafficL7Rx/1024,
			p.TrafficL7Tx/1024,
			p.BandwidthL7Rx/1024,
			p.BandwidthL7Tx/1024,
			p.RequestCount,
			p.ResponseCount,
			p.BlockedRequestCount,
			p.IPCount,
			p.BlockedIPCount,
			p.Code200,
			p.Code206,
			p.Code301,
			p.Code302,
			p.Code400,
			p.Code403,
			p.Code404,
			p.Code444,
			p.Code499,
			p.Code500,
			p.Code501,
			p.Code502,
			p.Code503,
			p.Code504,
			p.Code904,
			p.Code929,
			p.Code978,
			p.GetCount,
			p.PostCount,
			p.DeleteCount,
			p.PutCount,
			p.HeadCount,
			p.PatchCount,
			p.OptionsCount,
			p.OthersCount,
			p.HTTP10Count,
			p.HTTP11Count,
			p.HTTP2Count,
			p.HTTP3Count,
		)
	}

	if len(valuePlaceholders) == 0 {
		return nil
	}

	query := `
		INSERT INTO site_traffic_stats (
			server_id,
			site_id,
			bucket_ts,
			traffic_l7_rx,
			traffic_l7_tx,
			bandwidth_l7_rx,
			bandwidth_l7_tx,
			request_count,
			response_count,
			blocked_request_count,
			ip_count,
			blocked_ip_count,
			code200,
			code206,
			code301,
			code302,
			code400,
			code403,
			code404,
			code444,
			code499,
			code500,
			code501,
			code502,
			code503,
			code504,
			code904,
			code929,
			code978,
			get_count,
			post_count,
			delete_count,
			put_count,
			head_count,
			patch_count,
			options_count,
			others_count,
			http1_0_count,
			http1_1_count,
			http2_count,
			http3_count
		) VALUES ` + strings.Join(valuePlaceholders, ",") + `
		ON DUPLICATE KEY UPDATE
			traffic_l7_rx = VALUES(traffic_l7_rx),
			traffic_l7_tx = VALUES(traffic_l7_tx),
			bandwidth_l7_rx = VALUES(bandwidth_l7_rx),
			bandwidth_l7_tx = VALUES(bandwidth_l7_tx),
			request_count = VALUES(request_count),
			response_count = VALUES(response_count),
			blocked_request_count = VALUES(blocked_request_count),
			ip_count = VALUES(ip_count),
			blocked_ip_count = VALUES(blocked_ip_count),
			code200 = VALUES(code200),
			code206 = VALUES(code206),
			code301 = VALUES(code301),
			code302 = VALUES(code302),
			code400 = VALUES(code400),
			code403 = VALUES(code403),
			code404 = VALUES(code404),
			code444 = VALUES(code444),
			code499 = VALUES(code499),
			code500 = VALUES(code500),
			code501 = VALUES(code501),
			code502 = VALUES(code502),
			code503 = VALUES(code503),
			code504 = VALUES(code504),
			code904 = VALUES(code904),
			code929 = VALUES(code929),
			code978 = VALUES(code978),
			get_count = VALUES(get_count),
			post_count = VALUES(post_count),
			delete_count = VALUES(delete_count),
			put_count = VALUES(put_count),
			head_count = VALUES(head_count),
			patch_count = VALUES(patch_count),
			options_count = VALUES(options_count),
			others_count = VALUES(others_count),
			http1_0_count = VALUES(http1_0_count),
			http1_1_count = VALUES(http1_1_count),
			http2_count = VALUES(http2_count),
			http3_count = VALUES(http3_count)`

	_, err := dbConn.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("insert site_traffic_stats: %w", err)
	}
	return nil
}

func insertDomainRequestBucket(ctx context.Context, dbConn *sql.DB, serverID int64, bucket time.Time, data domainRequestStatsBucketResponse) error {
	if len(data.DomainRequestStats) == 0 {
		return nil
	}

	valuePlaceholders := make([]string, 0, len(data.DomainRequestStats))
	args := make([]any, 0, len(data.DomainRequestStats)*10)

	for _, row := range data.DomainRequestStats {
		domain := strings.TrimSpace(row.Domain)
		if domain == "" {
			continue
		}
		if row.RequestCount <= 0 && row.TrafficL7Rx <= 0 && row.TrafficL7Tx <= 0 {
			continue
		}
		valuePlaceholders = append(valuePlaceholders, "(?, ?, ?, UNHEX(MD5(?)), ?, ?, ?, ?, ?, ?)")
		args = append(args,
			serverID,
			row.SiteID,
			bucket,
			domain,
			domain,
			row.RequestCount,
			int64(row.TrafficL7Rx/1024),
			int64(row.TrafficL7Tx/1024),
			int64(row.BandwidthL7Rx/1024),
			int64(row.BandwidthL7Tx/1024),
		)
	}

	if len(valuePlaceholders) == 0 {
		return nil
	}

	query := `
		INSERT INTO domain_request_stats (
			server_id,
			site_id,
			bucket_ts,
			domain_hash,
			request_domain,
			request_count,
			traffic_l7_rx,
			traffic_l7_tx,
			bandwidth_l7_rx,
			bandwidth_l7_tx
		) VALUES ` + strings.Join(valuePlaceholders, ",") + `
		ON DUPLICATE KEY UPDATE
			request_domain = VALUES(request_domain),
			request_count = VALUES(request_count),
			traffic_l7_rx = VALUES(traffic_l7_rx),
			traffic_l7_tx = VALUES(traffic_l7_tx),
			bandwidth_l7_rx = VALUES(bandwidth_l7_rx),
			bandwidth_l7_tx = VALUES(bandwidth_l7_tx)`

	_, err := dbConn.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("insert domain_request_stats: %w", err)
	}
	return nil
}
func insertServerTrafficSnapshot(
	ctx context.Context,
	dbConn *sql.DB,
	serverID int64,
	bucket time.Time,
	p serverTrafficStatsPayload,
) error {

	query := `
		INSERT INTO server_traffic_stats (
			server_id,
			bucket_ts,
			traffic_nic_rx,
			traffic_nic_tx,
			traffic_l7_rx,
			traffic_l7_tx,
			bandwidth_nic_rx,
			bandwidth_nic_tx,
			bandwidth_l7_rx,
			bandwidth_l7_tx,
			request_count,
			response_count,
			blocked_request_count,
			ip_count,
			blocked_ip_count,
			code200,
			code206,
			code301,
			code302,
			code400,
			code403,
			code404,
			code444,
			code499,
			code500,
			code502,
			code503,
			code504,
			code904,
			code929,
			code978,
			get_count,
			post_count,
			delete_count,
			put_count,
			head_count,
			patch_count,
			options_count,
			others_count,
			http1_0_count,
			http1_1_count,
			http2_count,
			http3_count
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		)
		ON DUPLICATE KEY UPDATE
			traffic_nic_rx = VALUES(traffic_nic_rx),
			traffic_nic_tx = VALUES(traffic_nic_tx),
			traffic_l7_rx = VALUES(traffic_l7_rx),
			traffic_l7_tx = VALUES(traffic_l7_tx),
			bandwidth_nic_rx = VALUES(bandwidth_nic_rx),
			bandwidth_nic_tx = VALUES(bandwidth_nic_tx),
			bandwidth_l7_rx = VALUES(bandwidth_l7_rx),
			bandwidth_l7_tx = VALUES(bandwidth_l7_tx),
			request_count = VALUES(request_count),
			response_count = VALUES(response_count),
			blocked_request_count = VALUES(blocked_request_count),
			ip_count = VALUES(ip_count),
			blocked_ip_count = VALUES(blocked_ip_count),
			code200 = VALUES(code200),
			code206 = VALUES(code206),
			code301 = VALUES(code301),
			code302 = VALUES(code302),
			code400 = VALUES(code400),
			code403 = VALUES(code403),
			code404 = VALUES(code404),
			code444 = VALUES(code444),
			code499 = VALUES(code499),
			code500 = VALUES(code500),
			code502 = VALUES(code502),
			code503 = VALUES(code503),
			code504 = VALUES(code504),
			code904 = VALUES(code904),
			code929 = VALUES(code929),
			code978 = VALUES(code978),
			get_count = VALUES(get_count),
			post_count = VALUES(post_count),
			delete_count = VALUES(delete_count),
			put_count = VALUES(put_count),
			head_count = VALUES(head_count),
			patch_count = VALUES(patch_count),
			options_count = VALUES(options_count),
			others_count = VALUES(others_count),
			http1_0_count = VALUES(http1_0_count),
			http1_1_count = VALUES(http1_1_count),
			http2_count = VALUES(http2_count),
			http3_count = VALUES(http3_count)
	`

	_, err := dbConn.ExecContext(
		ctx,
		query,
		serverID,
		bucket,
		p.TrafficNicRx/1024,
		p.TrafficNicTx/1024,
		p.TrafficL7Rx/1024,
		p.TrafficL7Tx/1024,
		p.BandwidthNicRx/1024,
		p.BandwidthNicTx/1024,
		p.BandwidthL7Rx/1024,
		p.BandwidthL7Tx/1024,
		p.RequestCount,
		p.ResponseCount,
		p.BlockedRequestCount,
		p.IPCount,
		p.BlockedIPCount,
		p.Code200,
		p.Code206,
		p.Code301,
		p.Code302,
		p.Code400,
		p.Code403,
		p.Code404,
		p.Code444,
		p.Code499,
		p.Code500,
		p.Code502,
		p.Code503,
		p.Code504,
		p.Code904,
		p.Code929,
		p.Code978,
		p.GetCount,
		p.PostCount,
		p.DeleteCount,
		p.PutCount,
		p.HeadCount,
		p.PatchCount,
		p.OptionsCount,
		p.OthersCount,
		p.HTTP10Count,
		p.HTTP11Count,
		p.HTTP2Count,
		p.HTTP3Count,
	)
	if err != nil {
		return fmt.Errorf("insert server_traffic_stats: %w", err)
	}

	return nil
}

func buildIPRequestStatsClientConfig(cfg config.Config) ipRequestStatsClientConfig {
	port := strings.TrimSpace(cfg.MetricsPort)
	if port == "" {
		port = "9000"
	}

	// Timestamps endpoint is fixed unless overridden in code:
	timestampsPath := "/ip_request_stats/timestamps"
	if !strings.HasPrefix(timestampsPath, "/") {
		timestampsPath = "/" + timestampsPath
	}

	ipBucketPath := strings.TrimSpace(cfg.MetricsBucketPath)
	if ipBucketPath == "" {
		ipBucketPath = "/ip_request_stats"
	}
	if !strings.HasPrefix(ipBucketPath, "/") {
		ipBucketPath = "/" + ipBucketPath
	}

	ispBucketPath := strings.TrimSpace(cfg.MetricsIspBucketPath)
	if ispBucketPath == "" {
		ispBucketPath = "/isp_request_stats"
	}
	if !strings.HasPrefix(ispBucketPath, "/") {
		ispBucketPath = "/" + ispBucketPath
	}

	countryBucketPath := strings.TrimSpace(cfg.MetricsCountryBucketPath)
	if countryBucketPath == "" {
		countryBucketPath = "/country_request_stats"
	}
	if !strings.HasPrefix(countryBucketPath, "/") {
		countryBucketPath = "/" + countryBucketPath
	}

	refererBucketPath := strings.TrimSpace(cfg.MetricsRefererBucketPath)
	if refererBucketPath == "" {
		refererBucketPath = "/referer_request_stats"
	}
	if !strings.HasPrefix(refererBucketPath, "/") {
		refererBucketPath = "/" + refererBucketPath
	}

	urlBucketPath := strings.TrimSpace(cfg.MetricsURLBucketPath)
	if urlBucketPath == "" {
		urlBucketPath = "/url_request_stats"
	}
	if !strings.HasPrefix(urlBucketPath, "/") {
		urlBucketPath = "/" + urlBucketPath
	}

	userAgentBucketPath := strings.TrimSpace(cfg.MetricsUserAgentBucketPath)
	if userAgentBucketPath == "" {
		userAgentBucketPath = "/useragent_request_stats"
	}
	if !strings.HasPrefix(userAgentBucketPath, "/") {
		userAgentBucketPath = "/" + userAgentBucketPath
	}

	serverTrafficPath := strings.TrimSpace(cfg.MetricsServerTrafficPath)
	if serverTrafficPath == "" {
		serverTrafficPath = "/server_traffic_stats"
	}
	if !strings.HasPrefix(serverTrafficPath, "/") {
		serverTrafficPath = "/" + serverTrafficPath
	}

	siteTrafficPath := strings.TrimSpace(cfg.MetricsSiteTrafficPath)
	if siteTrafficPath == "" {
		siteTrafficPath = "/site_traffic_stats"
	}
	if !strings.HasPrefix(siteTrafficPath, "/") {
		siteTrafficPath = "/" + siteTrafficPath
	}

	domainRequestPath := strings.TrimSpace(cfg.MetricsDomainRequestPath)
	if domainRequestPath == "" {
		domainRequestPath = "/domain_request_stats"
	}
	if !strings.HasPrefix(domainRequestPath, "/") {
		domainRequestPath = "/" + domainRequestPath
	}

	intervalSeconds := cfg.MetricsPollIntervalSeconds
	if intervalSeconds <= 0 {
		intervalSeconds = 30
	}

	return ipRequestStatsClientConfig{
		port:                port,
		timestampsPath:      timestampsPath,
		ipBucketPath:        ipBucketPath,
		ispBucketPath:       ispBucketPath,
		countryBucketPath:   countryBucketPath,
		refererBucketPath:   refererBucketPath,
		urlBucketPath:       urlBucketPath,
		userAgentBucketPath: userAgentBucketPath,
		serverTrafficPath:   serverTrafficPath,
		siteTrafficPath:     siteTrafficPath,
		domainRequestPath:   domainRequestPath,
		interval:            time.Duration(intervalSeconds) * time.Second,
	}
}
