package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/store"
)

type edgeConfigureReportPayload struct {
	Token                   string                 `json:"token"`
	Command                 string                 `json:"command"`
	ReportedAt              flexibleInt64          `json:"reported_at"`
	IncludeSSLPems          bool                   `json:"include_ssl_pems"`
	WhitelistCount          int                    `json:"whitelist_count"`
	BlocklistCount          int                    `json:"blocklist_count"`
	SiteCount               int                    `json:"site_count"`
	TemporaryBlacklistCount int                    `json:"temporaryblacklist_count"`
	Whitelist               []edgeL4WhitelistEntry `json:"whitelist"`
	Blocklist               []edgeL4BlocklistEntry `json:"blocklist"`
	L4                      edgeL4ConfigureSection `json:"l4"`
	L7                      edgeL7ConfigureSection `json:"l7"`
}

type edgeL4WhitelistEntry struct {
	IP      string         `json:"ip"`
	Reason  string         `json:"reason"`
	Created flexibleString `json:"created"`
}

type edgeL4BlocklistEntry struct {
	IP       string         `json:"ip"`
	Type     string         `json:"type"`
	Duration flexibleInt64  `json:"duration"`
	Reason   string         `json:"reason"`
	Created  flexibleString `json:"created"`
}

type edgeL4ConfigureSection struct {
	// Angelos may send string or numeric values for firewall.config keys.
	FirewallConfig      map[string]flexibleString `json:"firewall_config"`
	FirewallConfigError any                       `json:"firewall_config_error"`
	Whitelist           []edgeL4WhitelistEntry    `json:"whitelist"`
	Blocklist           []edgeL4BlocklistEntry    `json:"blocklist"`
}

type edgeL7ConfigureSection struct {
	Edge  edgeL7EdgeSection            `json:"edge"`
	Sites map[string]edgeL7SiteSection `json:"sites"`
	Files map[string]any               `json:"files"`
}

type edgeL7EdgeSection struct {
	ListeningPorts     []edgeListeningPortEntry      `json:"listeningports"`
	TemporaryBlacklist []edgeTemporaryBlacklistEntry `json:"temporaryblacklist"`
	ACLRules           []map[string]any              `json:"acl_rules"`
	ACLApplyRules      []map[string]any              `json:"acl_apply_rules"`
	LegacyGlobal       map[string]any                `json:"legacy_global"`
}

type edgeListeningPortEntry struct {
	ID          flexibleInt64  `json:"id"`
	ServerID    flexibleInt64  `json:"serverId"`
	Port        flexibleInt64  `json:"port"`
	Protocol    string         `json:"protocol"`
	Description string         `json:"description"`
	Status      string         `json:"status"`
}

type edgeTemporaryBlacklistEntry struct {
	IP          string         `json:"ip"`
	URL         string         `json:"url"`
	Country     string         `json:"country"`
	City        string         `json:"city"`
	BlockedAt   flexibleString `json:"blocked_at"`
	TTL         flexibleInt64  `json:"ttl"`
	TriggerRule string         `json:"trigger_rule"`
	SiteID      flexibleInt64  `json:"site_id"`
	SiteIDCamel flexibleInt64  `json:"siteId"`
}

type edgeL7SiteSection struct {
	Domain          string              `json:"domain"`
	Domains         []string            `json:"domains"`
	WAF             map[string]any      `json:"waf"`
	Cache           []map[string]any    `json:"cache"`
	Listening       edgeL7SiteListening `json:"listening"`
	UpstreamServers []edgeUpstreamEntry `json:"upstreamservers"`
	Compress        map[string]any      `json:"compress"`
	SSL             map[string]any      `json:"ssl"`
}

type edgeL7SiteListening struct {
	HTTPPorts  []edgeListeningPortEntry `json:"http_ports"`
	HTTPSPorts []edgeListeningPortEntry `json:"https_ports"`
}

type edgeUpstreamEntry struct {
	IPPort      string `json:"ip_port"`
	Description string `json:"description"`
	Protocol    string `json:"protocol"`
}

type edgeConfigureSyncResult struct {
	Status             string `json:"status"`
	ServerID           int64  `json:"serverId"`
	WhitelistSynced    int    `json:"whitelistSynced"`
	BlocklistSynced    int    `json:"blocklistSynced"`
	ListeningPorts     int    `json:"listeningPortsSynced"`
	TemporaryBlacklist int    `json:"temporaryBlacklistSynced"`
	L4ConfigUpdated    bool   `json:"l4ConfigUpdated"`
	SitesTouched       int    `json:"sitesTouched"`
	ReportedAt         int64  `json:"reportedAt,omitempty"`
}

func reportEdgeConfigureHandler(
	servers store.ServerStore,
	l4 store.L4Store,
	l4Whitelist store.L4WhitelistStore,
	l4Blacklist store.L4BlacklistStore,
	listeningPorts store.ListeningPortStore,
	blacklist store.BlacklistStore,
	sites store.SiteStore,
	upstreamServers store.UpstreamServerStore,
	compressSettings store.CompressStore,
	siteListeningPorts store.SiteListeningPortStore,
	l7BlockEvents store.L7BlockEventStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var payload edgeConfigureReportPayload
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&payload); err != nil {
			log.Printf("[api] report_edge_configure invalid JSON: %v", err)
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		payload.Token = strings.TrimSpace(payload.Token)
		payload.Command = strings.TrimSpace(payload.Command)
		if payload.Token == "" {
			writeError(w, http.StatusForbidden, "missing token")
			return
		}
		if payload.Command != "" && !strings.EqualFold(payload.Command, "report_edge_configure") {
			writeError(w, http.StatusBadRequest, "unsupported command")
			return
		}

		server, err := servers.GetByToken(r.Context(), payload.Token)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusForbidden, "invalid token")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to validate token")
			return
		}

		result := edgeConfigureSyncResult{
			Status:     "success",
			ServerID:   server.ID,
			ReportedAt: payload.ReportedAt.Int64(),
		}
		firewallConfig := flexibleStringMap(payload.L4.FirewallConfig)

		whitelistEntries := payload.L4.Whitelist
		if len(whitelistEntries) == 0 {
			whitelistEntries = payload.Whitelist
		}
		whitelistInputs := make([]store.L4WhitelistInput, 0, len(whitelistEntries))
		for _, entry := range whitelistEntries {
			ip := strings.TrimSpace(entry.IP)
			if ip == "" {
				continue
			}
			whitelistInputs = append(whitelistInputs, store.L4WhitelistInput{
				IPAddress: ip,
				Reason:    strings.TrimSpace(entry.Reason),
			})
		}
		if err := l4Whitelist.ReplaceByServer(r.Context(), server.ID, whitelistInputs); err != nil {
			log.Printf("[api] report_edge_configure serverID=%d whitelist sync failed: %v", server.ID, err)
			writeError(w, http.StatusInternalServerError, "failed to sync L4 whitelist")
			return
		}
		result.WhitelistSynced = len(whitelistInputs)

		// The edge blocklist snapshot is the live XDP block table. It is shown on
		// the temporary-block page. l4_blacklist stays the permanent list.
		blocklistEntries := payload.L4.Blocklist
		if len(blocklistEntries) == 0 {
			blocklistEntries = payload.Blocklist
		}
		defaultTTL := configuredBlackIPDuration(firewallConfig)
		if defaultTTL <= 0 {
			if cfg, err := l4.GetByServerID(r.Context(), server.ID); err == nil && cfg.BlackIPDuration > 0 {
				defaultTTL = int64(cfg.BlackIPDuration)
			}
		}
		liveBlocks := make([]store.TemporaryBlacklistPayload, 0, len(blocklistEntries))
		for _, entry := range blocklistEntries {
			ip := strings.TrimSpace(entry.IP)
			if ip == "" {
				continue
			}
			reason := strings.TrimSpace(entry.Reason)
			if reason == "" {
				reason = strings.TrimSpace(entry.Type)
			}
			// black_ip_duration is the TTL configured on the edge. The snapshot's
			// per-IP duration is often the 3600s default, not that setting.
			ttl := defaultTTL
			if ttl <= 0 {
				ttl = entry.Duration.Int64()
			}
			liveBlocks = append(liveBlocks, store.TemporaryBlacklistPayload{
				IP:          ip,
				Reason:      reason,
				BlockedAt:   blocklistBlockedAt(entry.Created.String()),
				TTL:         ttl,
				TriggerRule: "l4ddos",
				ServerID:    server.ID,
				Server:      server.Name,
			})
		}
		if err := blacklist.ReplaceL4Temporary(r.Context(), server.ID, liveBlocks); err != nil {
			log.Printf("[api] report_edge_configure serverID=%d live block sync failed: %v", server.ID, err)
			writeError(w, http.StatusInternalServerError, "failed to sync live blocks")
			return
		}
		result.BlocklistSynced = len(liveBlocks)

		if !hasFirewallConfigError(payload.L4.FirewallConfigError) && len(firewallConfig) > 0 {
			cfg, err := l4.GetByServerID(r.Context(), server.ID)
			if err != nil {
				if !store.IsNotFound(err) {
					// Non-fatal: lists still sync; Angelos will retry config next minute.
					log.Printf("[api] report_edge_configure serverID=%d load L4 config failed: %v", server.ID, err)
				}
			} else {
				applyFirewallConfigMap(&cfg, firewallConfig)
				store.ApplyFirewallConfigRaw(&cfg, firewallConfig)
				if err := l4.UpdateByServerID(r.Context(), server.ID, cfg); err != nil {
					log.Printf("[api] report_edge_configure serverID=%d update L4 config failed: %v", server.ID, err)
				} else {
					result.L4ConfigUpdated = true
				}
			}
		}

		portInputs := make([]store.ListeningPortInput, 0, len(payload.L7.Edge.ListeningPorts))
		for _, port := range payload.L7.Edge.ListeningPorts {
			portNum := int(port.Port.Int64())
			if portNum <= 0 {
				continue
			}
			portInputs = append(portInputs, store.ListeningPortInput{
				Port:        portNum,
				Protocol:    port.Protocol,
				Description: port.Description,
				Status:      port.Status,
			})
		}
		syncedPorts, err := listeningPorts.ReplaceByServer(r.Context(), server.ID, portInputs)
		if err != nil {
			// Non-fatal: lists/L4 still sync; Angelos will retry ports next minute.
			log.Printf("[api] report_edge_configure serverID=%d listening ports sync failed: %v", server.ID, err)
			syncedPorts = nil
		}
		result.ListeningPorts = len(syncedPorts)

		tempPayloads := make([]store.TemporaryBlacklistPayload, 0, len(payload.L7.Edge.TemporaryBlacklist))
		for _, entry := range payload.L7.Edge.TemporaryBlacklist {
			ip := strings.TrimSpace(entry.IP)
			if ip == "" {
				continue
			}
			siteID := entry.SiteID.Int64()
			if siteID == 0 {
				siteID = entry.SiteIDCamel.Int64()
			}
			ttl := entry.TTL.Int64()
			trigger := strings.TrimSpace(entry.TriggerRule)
			if isL4BlockRule(trigger) && defaultTTL > 0 {
				ttl = defaultTTL
			}
			tempPayloads = append(tempPayloads, store.TemporaryBlacklistPayload{
				IP:          ip,
				URL:         strings.TrimSpace(entry.URL),
				Country:     strings.TrimSpace(entry.Country),
				City:        strings.TrimSpace(entry.City),
				BlockedAt:   strings.TrimSpace(entry.BlockedAt.String()),
				TTL:         ttl,
				TriggerRule: trigger,
				ServerID:    server.ID,
				SiteID:      siteID,
				Server:      server.Name,
			})
		}
		if err := blacklist.ReplaceForServer(r.Context(), server.ID, tempPayloads); err != nil {
			log.Printf("[api] report_edge_configure serverID=%d temporary blacklist sync failed: %v", server.ID, err)
			writeError(w, http.StatusInternalServerError, "failed to sync temporary blacklist")
			return
		}
		result.TemporaryBlacklist = len(tempPayloads)
		if l7BlockEvents != nil && len(tempPayloads) > 0 {
			history := make([]store.L7BlockEventInput, 0, len(tempPayloads))
			for _, item := range tempPayloads {
				if event, ok := store.L7BlockEventFromTempPayload(item); ok {
					history = append(history, event)
				}
			}
			if err := l7BlockEvents.RecordMany(r.Context(), history); err != nil {
				log.Printf("[api] report_edge_configure serverID=%d durable L7 block history failed: %v", server.ID, err)
			}
		}

		portIDByKey := make(map[string]int64, len(syncedPorts))
		for _, port := range syncedPorts {
			key := listeningPortKey(port.Port, port.Protocol)
			portIDByKey[key] = port.ID
		}

		for siteKey, siteCfg := range payload.L7.Sites {
			siteID, err := strconv.ParseInt(strings.TrimSpace(siteKey), 10, 64)
			if err != nil || siteID == 0 {
				continue
			}
			site, err := sites.Get(r.Context(), siteID)
			if err != nil {
				if store.IsNotFound(err) {
					continue
				}
				log.Printf("[api] report_edge_configure serverID=%d load site %d failed: %v", server.ID, siteID, err)
				continue
			}
			if !siteAssignedToServer(site, server.ID) {
				continue
			}

			if err := syncSiteCompress(r.Context(), compressSettings, siteID, siteCfg.Compress); err != nil {
				log.Printf("[api] report_edge_configure serverID=%d site %d compress sync failed: %v", server.ID, siteID, err)
			}
			if err := syncSiteUpstreams(r.Context(), upstreamServers, siteID, siteCfg.UpstreamServers); err != nil {
				log.Printf("[api] report_edge_configure serverID=%d site %d upstream sync failed: %v", server.ID, siteID, err)
			}
			if err := syncSiteListeningSelection(r.Context(), siteListeningPorts, siteID, server.ID, siteCfg.Listening, portIDByKey); err != nil {
				log.Printf("[api] report_edge_configure serverID=%d site %d listening selection sync failed: %v", server.ID, siteID, err)
			}
			result.SitesTouched++
		}

		log.Printf(
			"[api] report_edge_configure ok serverID=%d whitelist=%d blocklist=%d ports=%d tempBL=%d l4=%t sites=%d",
			server.ID,
			result.WhitelistSynced,
			result.BlocklistSynced,
			result.ListeningPorts,
			result.TemporaryBlacklist,
			result.L4ConfigUpdated,
			result.SitesTouched,
		)
		writeJSON(w, http.StatusOK, result)
	}
}

func normalizeL4AttachMode(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "skb", "generic":
		return "skb", true
	case "native", "np", "driver":
		return "native", true
	case "drv", "offload":
		return "drv", true
	case "hw", "hardware":
		return "hw", true
	default:
		return "", false
	}
}

func normalizeL4Sensitivity(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low", "l":
		return "Low", true
	case "medium", "med", "m":
		return "Medium", true
	case "high", "h":
		return "High", true
	default:
		return "", false
	}
}

func normalizeL4ProtectionMode(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	switch strings.ToLower(trimmed) {
	case "always on", "always_on", "alwayson", "on", "active":
		return "Always On", true
	case "monitor", "detection", "detect":
		return "Monitor", true
	default:
		// Preserve exact DB enum labels if Angelos already sends them.
		if trimmed == "Always On" || trimmed == "Monitor" {
			return trimmed, true
		}
		return "", false
	}
}

func configuredBlackIPDuration(raw map[string]string) int64 {
	for _, key := range []string{"black_ip_duration", "blackIpDuration"} {
		for existing, value := range raw {
			if !strings.EqualFold(existing, key) {
				continue
			}
			if parsed, ok := parseFlexibleInt(value); ok && parsed > 0 {
				return int64(parsed)
			}
		}
	}
	return 0
}

func blocklistBlockedAt(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return strconv.FormatInt(time.Now().UTC().Unix(), 10)
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if parsed, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			return strconv.FormatInt(parsed.Unix(), 10)
		}
	}
	if sec, err := strconv.ParseInt(raw, 10, 64); err == nil && sec > 0 {
		return strconv.FormatInt(sec, 10)
	}
	return strconv.FormatInt(time.Now().UTC().Unix(), 10)
}

func siteAssignedToServer(site store.Site, serverID int64) bool {
	for _, id := range site.ServerIDs {
		if id == serverID {
			return true
		}
	}
	return false
}

func listeningPortKey(port int, protocol string) string {
	return strconv.Itoa(port) + "|" + strings.ToUpper(strings.TrimSpace(protocol))
}

func applyFirewallConfigMap(cfg *store.L4Config, raw map[string]string) {
	if cfg == nil || len(raw) == 0 {
		return
	}
	get := func(keys ...string) (string, bool) {
		for _, key := range keys {
			if value, ok := raw[key]; ok {
				return strings.TrimSpace(value), true
			}
			for existingKey, value := range raw {
				if strings.EqualFold(existingKey, key) {
					return strings.TrimSpace(value), true
				}
			}
		}
		return "", false
	}
	setString := func(dst *string, keys ...string) {
		if value, ok := get(keys...); ok {
			*dst = value
		}
	}
	setBool := func(dst *bool, keys ...string) {
		if value, ok := get(keys...); ok {
			if parsed, ok := parseFlexibleBool(value); ok {
				*dst = parsed
			}
		}
	}
	setInt := func(dst *int, keys ...string) {
		if value, ok := get(keys...); ok {
			if parsed, ok := parseFlexibleInt(value); ok {
				*dst = parsed
			}
		}
	}

	setString(&cfg.Dev, "dev")
	setInt(&cfg.BlackIPDuration, "black_ip_duration", "blackIpDuration")

	// MySQL ENUMs — ignore unknown Angelos values instead of failing the whole sync.
	if value, ok := get("attach_mode", "attachMode"); ok {
		if normalized, ok := normalizeL4AttachMode(value); ok {
			cfg.AttachMode = normalized
		}
	}
	if value, ok := get("sensitivity"); ok {
		if normalized, ok := normalizeL4Sensitivity(value); ok {
			cfg.Sensitivity = normalized
		}
	}
	if value, ok := get("protection_mode", "protectionMode"); ok {
		if normalized, ok := normalizeL4ProtectionMode(value); ok {
			cfg.ProtectionMode = normalized
		}
	}

	setBool(&cfg.SynValid, "syn_valid", "synValid")
	setInt(&cfg.SynThreshold, "syn_threshold", "synThreshold")
	setInt(&cfg.SynBurstPkt, "syn_burst_pkt", "synBurstPkt")
	setInt(&cfg.SynBurstCountPerSec, "syn_burst_count_per_sec", "synBurstCountPerSec")
	setInt(&cfg.SynFixedThreshold, "syn_fixed_threshold", "synFixedThreshold")
	setInt(&cfg.SynFixedCheckDuration, "syn_fixed_check_duration", "synFixedCheckDuration")
	setInt(&cfg.ChallengeTimeout, "challenge_timeout", "challengeTimeout")
	setInt(&cfg.SynProtectionDuration, "syn_protection_duration", "synProtectionDuration")

	setBool(&cfg.AckValid, "ack_valid", "ackValid")
	setInt(&cfg.AckThreshold, "ack_threshold", "ackThreshold")
	setInt(&cfg.AckBurstPkt, "ack_burst_pkt", "ackBurstPkt")
	setInt(&cfg.AckBurstCountPerSec, "ack_burst_count_per_sec", "ackBurstCountPerSec")
	setInt(&cfg.AckFixedThreshold, "ack_fixed_threshold", "ackFixedThreshold")
	setInt(&cfg.AckFixedCheckDuration, "ack_fixed_check_duration", "ackFixedCheckDuration")
	setInt(&cfg.AckProtectionDuration, "ack_protection_duration", "ackProtectionDuration")

	setBool(&cfg.RstValid, "rst_valid", "rstValid")
	setInt(&cfg.RstThreshold, "rst_threshold", "rstThreshold")
	setInt(&cfg.RstBurstPkt, "rst_burst_pkt", "rstBurstPkt")
	setInt(&cfg.RstBurstCountPerSec, "rst_burst_count_per_sec", "rstBurstCountPerSec")
	setInt(&cfg.RstFixedThreshold, "rst_fixed_threshold", "rstFixedThreshold")
	setInt(&cfg.RstFixedCheckDuration, "rst_fixed_check_duration", "rstFixedCheckDuration")
	setInt(&cfg.RstProtectionDuration, "rst_protection_duration", "rstProtectionDuration")

	setBool(&cfg.StompValid, "stomp_valid", "stompValid", "psh_valid", "pshValid")
	setInt(&cfg.StompThreshold, "stomp_threshold", "stompThreshold", "psh_threshold", "pshThreshold")
	setInt(&cfg.StompBurstPkt, "stomp_burst_pkt", "stompBurstPkt", "psh_burst_pkt", "pshBurstPkt")
	setInt(&cfg.StompBurstCountPerSec, "stomp_burst_count_per_sec", "stompBurstCountPerSec", "psh_burst_count_per_sec", "pshBurstCountPerSec")
	setInt(&cfg.StompFixedThreshold, "stomp_fixed_threshold", "stompFixedThreshold", "psh_fixed_threshold", "pshFixedThreshold")
	setInt(&cfg.StompFixedCheckDuration, "stomp_fixed_check_duration", "stompFixedCheckDuration", "psh_fixed_check_duration", "pshFixedCheckDuration")
	setInt(&cfg.StompProtectionDuration, "stomp_protection_duration", "stompProtectionDuration", "psh_protection_duration", "pshProtectionDuration")

	setBool(&cfg.SocketValid, "socket_valid", "socketValid")
	setInt(&cfg.SocketFinThreshold, "socket_fin_threshold", "socketFinThreshold")
	setInt(&cfg.SocketFixedThreshold, "socket_fixed_threshold", "socketFixedThreshold")
	setInt(&cfg.SocketFixedCheckDuration, "socket_fixed_check_duration", "socketFixedCheckDuration")

	setBool(&cfg.IcmpValid, "icmp_valid", "icmpValid")
	setInt(&cfg.IcmpThreshold, "icmp_threshold", "icmpThreshold")
	setInt(&cfg.IcmpBurstPkt, "icmp_burst_pkt", "icmpBurstPkt")
	setInt(&cfg.IcmpBurstCountPerSec, "icmp_burst_count_per_sec", "icmpBurstCountPerSec")
	setInt(&cfg.IcmpFixedThreshold, "icmp_fixed_threshold", "icmpFixedThreshold")
	setInt(&cfg.IcmpFixedCheckDuration, "icmp_fixed_check_duration", "icmpFixedCheckDuration")
	setInt(&cfg.IcmpProtectionDuration, "icmp_protection_duration", "icmpProtectionDuration")

	setBool(&cfg.UdpValid, "udp_valid", "udpValid")
	setInt(&cfg.UdpThreshold, "udp_threshold", "udpThreshold")
	setInt(&cfg.UdpBurstPkt, "udp_burst_pkt", "udpBurstPkt")
	setInt(&cfg.UdpBurstCountPerSec, "udp_burst_count_per_sec", "udpBurstCountPerSec")
	setInt(&cfg.UdpFixedThreshold, "udp_fixed_threshold", "udpFixedThreshold")
	setInt(&cfg.UdpFixedCheckDuration, "udp_fixed_check_duration", "udpFixedCheckDuration")
	setInt(&cfg.UdpProtectionDuration, "udp_protection_duration", "udpProtectionDuration")

	setBool(&cfg.GreValid, "gre_valid", "greValid")
	setInt(&cfg.GreThreshold, "gre_threshold", "greThreshold")
	setInt(&cfg.GreBurstPkt, "gre_burst_pkt", "greBurstPkt")
	setInt(&cfg.GreBurstCountPerSec, "gre_burst_count_per_sec", "greBurstCountPerSec")
	setInt(&cfg.GreFixedThreshold, "gre_fixed_threshold", "greFixedThreshold")
	setInt(&cfg.GreFixedCheckDuration, "gre_fixed_check_duration", "greFixedCheckDuration")
	setInt(&cfg.GreProtectionDuration, "gre_protection_duration", "greProtectionDuration")

	setBool(&cfg.TcpSegCheck, "tcp_seg_check", "tcpSegCheck")
	setBool(&cfg.GeoCheck, "geo_check", "geoCheck")
	setString(&cfg.GeoDbIpv4Path, "geo_db_ipv4_path", "geoDbIpv4Path")
	setString(&cfg.GeoDbLocationPath, "geo_db_location_path", "geoDbLocationPath")
	if value, ok := get("geo_allow_countries", "geoAllowCountries"); ok {
		cfg.GeoAllowCountries = splitCSVFlexible(value)
	}
	setBool(&cfg.GeoCountriesBlockMode, "geo_countries_block_mode", "geoCountriesBlockMode")
	setBool(&cfg.TcpConnectionLimitCheck, "tcp_connection_limit_check", "tcpConnectionLimitCheck")
	setInt(&cfg.TcpConnectionLimitCnt, "tcp_connection_limit_cnt", "tcpConnectionLimitCnt")
}

func parseFlexibleBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enable", "enabled":
		return true, true
	case "0", "false", "no", "off", "disable", "disabled":
		return false, true
	default:
		return false, false
	}
}

func parseFlexibleInt(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func splitCSVFlexible(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key := strings.ToUpper(part)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, part)
	}
	return out
}

func syncSiteCompress(ctx context.Context, compress store.CompressStore, siteID int64, raw map[string]any) error {
	if compress == nil || len(raw) == 0 {
		return nil
	}
	input := store.CompressSettingsInput{}
	input.CSS = anyToBool(raw["css"])
	input.HTML = anyToBool(raw["html"])
	input.JS = anyToBool(raw["js"])
	input.Audio = anyToBool(raw["audio"])
	input.Font = anyToBool(raw["font"])
	input.Applications = anyToBool(raw["applications"])
	_, err := compress.UpsertBySiteID(ctx, siteID, input)
	return err
}

func syncSiteUpstreams(ctx context.Context, upstreams store.UpstreamServerStore, siteID int64, entries []edgeUpstreamEntry) error {
	if upstreams == nil {
		return nil
	}
	existing, err := upstreams.ListBySite(ctx, siteID)
	if err != nil {
		return err
	}

	desired := make(map[string]edgeUpstreamEntry, len(entries))
	for _, entry := range entries {
		address := store.NormalizeUpstreamAddress(entry.IPPort)
		if address == "" {
			continue
		}
		desired[address] = entry
	}

	existingByAddr := make(map[string]store.UpstreamServer, len(existing))
	for _, item := range existing {
		existingByAddr[store.NormalizeUpstreamAddress(item.Address)] = item
	}

	for addr, entry := range desired {
		protocol := entry.Protocol
		if protocol == "" {
			protocol = "http"
		}
		input := store.UpstreamServerInput{
			Address:     entry.IPPort,
			Protocol:    store.NormalizeUpstreamProtocol(protocol),
			Description: strings.TrimSpace(entry.Description),
			Status:      "ENABLE",
		}
		if current, ok := existingByAddr[addr]; ok {
			if _, err := upstreams.Update(ctx, siteID, current.ID, input); err != nil {
				return err
			}
			continue
		}
		if _, err := upstreams.Create(ctx, siteID, input); err != nil {
			return err
		}
	}

	var toDelete []int64
	for addr, item := range existingByAddr {
		if _, keep := desired[addr]; !keep {
			toDelete = append(toDelete, item.ID)
		}
	}
	if len(toDelete) > 0 {
		return upstreams.DeleteBatch(ctx, siteID, toDelete)
	}
	return nil
}

func syncSiteListeningSelection(
	ctx context.Context,
	sitePorts store.SiteListeningPortStore,
	siteID, serverID int64,
	listening edgeL7SiteListening,
	portIDByKey map[string]int64,
) error {
	if sitePorts == nil {
		return nil
	}
	var selected []int64
	seen := make(map[int64]struct{})
	add := func(list []edgeListeningPortEntry) {
		for _, port := range list {
			portNum := int(port.Port.Int64())
			if portNum <= 0 {
				continue
			}
			key := listeningPortKey(portNum, port.Protocol)
			id, ok := portIDByKey[key]
			if !ok {
				// Try alternate protocol casing / default HTTP
				if id, ok = portIDByKey[listeningPortKey(portNum, "HTTP")]; !ok {
					id, ok = portIDByKey[listeningPortKey(portNum, "HTTPS")]
				}
			}
			if !ok || id == 0 {
				continue
			}
			if _, exists := seen[id]; exists {
				continue
			}
			seen[id] = struct{}{}
			selected = append(selected, id)
		}
	}
	add(listening.HTTPPorts)
	add(listening.HTTPSPorts)
	return sitePorts.ReplaceForServer(ctx, siteID, serverID, selected)
}

func anyToBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		parsed, ok := parseFlexibleBool(v)
		return ok && parsed
	case json.Number:
		n, err := v.Int64()
		return err == nil && n != 0
	case float64:
		return v != 0
	case int:
		return v != 0
	case int64:
		return v != 0
	default:
		return false
	}
}

// flexibleString accepts JSON strings or numbers (Angelos often sends mixed types).
type flexibleString string

func (s flexibleString) String() string { return string(s) }

func (s *flexibleString) UnmarshalJSON(data []byte) error {
	data = bytesTrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*s = ""
		return nil
	}
	if data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		*s = flexibleString(str)
		return nil
	}
	if data[0] == 't' || data[0] == 'f' {
		var b bool
		if err := json.Unmarshal(data, &b); err != nil {
			return err
		}
		if b {
			*s = "1"
		} else {
			*s = "0"
		}
		return nil
	}
	var num json.Number
	if err := json.Unmarshal(data, &num); err != nil {
		return err
	}
	*s = flexibleString(num.String())
	return nil
}

// flexibleInt64 accepts JSON numbers or numeric strings.
type flexibleInt64 int64

func (n flexibleInt64) Int64() int64 { return int64(n) }

func (n *flexibleInt64) UnmarshalJSON(data []byte) error {
	data = bytesTrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*n = 0
		return nil
	}
	if data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		str = strings.TrimSpace(str)
		if str == "" {
			*n = 0
			return nil
		}
		// Allow "600s" style durations from Angelos.
		str = strings.TrimSuffix(str, "s")
		str = strings.TrimSuffix(str, "S")
		parsed, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			if f, ferr := strconv.ParseFloat(str, 64); ferr == nil {
				*n = flexibleInt64(f)
				return nil
			}
			return err
		}
		*n = flexibleInt64(parsed)
		return nil
	}
	var num json.Number
	if err := json.Unmarshal(data, &num); err != nil {
		return err
	}
	parsed, err := num.Int64()
	if err != nil {
		f, ferr := num.Float64()
		if ferr != nil {
			return err
		}
		*n = flexibleInt64(f)
		return nil
	}
	*n = flexibleInt64(parsed)
	return nil
}

func bytesTrimSpace(data []byte) []byte {
	return bytes.TrimSpace(data)
}

func flexibleStringMap(raw map[string]flexibleString) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for key, value := range raw {
		out[key] = value.String()
	}
	return out
}

func hasFirewallConfigError(value any) bool {
	if value == nil {
		return false
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case bool:
		return v
	case json.Number:
		return false
	case float64:
		return false
	default:
		// Object/array from a buggy edge build — treat as "config unreadable".
		return true
	}
}
