package api

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vue-project-backend/internal/remotesvc"
	"vue-project-backend/internal/store"
)

type attackDropPoint struct {
	Timestamp string `json:"timestamp"`
	Blocked   int64  `json:"blocked"`
	Allowed   int64  `json:"allowed"`
}

type attackTypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type attackSource struct {
	IP             string `json:"ip"`
	AttackType     string `json:"attackType"`
	FirstBlockedAt string `json:"firstBlockedAt"`
	LastBlockedAt  string `json:"lastBlockedAt"`
	ReleasesAt     string `json:"releasesAt"`
	Blocks         int    `json:"blocks"`
	Active         bool   `json:"active"`
}

type attackLogLine struct {
	Time string `json:"time"`
	Text string `json:"text"`
}

type attackConsoleResponse struct {
	Attack      store.SecurityEventPeriod `json:"attack"`
	ServerTime  string                    `json:"serverTime"`
	WindowStart string                    `json:"windowStart"`
	WindowEnd   string                    `json:"windowEnd"`
	Drops       []attackDropPoint         `json:"drops"`
	Sources     []attackSource            `json:"sources"`
	ActiveCount int                       `json:"activeCount"`
	SourceCount int                       `json:"sourceCount"`
	AttackTypes []attackTypeCount         `json:"attackTypes"`
	Protection  string                    `json:"protection"`
	SpartaLog   []attackLogLine           `json:"spartaLog"`
	SpartaError string                    `json:"spartaError,omitempty"`
}

const (
	defaultBlockTTL    = 60 * time.Second
	spartaCounterMatch = `(SYN|ACK|PSH|RST|FIN|UDP|ICMP|GRE|STOMP)[A-Z+]* *: *[0-9]`
	spartaLogLineLimit = 1500
	spartaLogCacheTTL  = 10 * time.Minute
	spartaFlushLag     = time.Minute
)

type cachedSpartaLog struct {
	lines   []attackLogLine
	expires time.Time
}

var (
	spartaLogCacheMu sync.Mutex
	spartaLogCache   = map[string]cachedSpartaLog{}
)

func attackConsoleHandler(
	securityEvents store.SecurityEventStore,
	servers store.ServerStore,
	l4Stats store.L4AttackStatsStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		reqID := strings.TrimSpace(r.URL.Query().Get("reqId"))
		if reqID == "" {
			writeError(w, http.StatusBadRequest, "reqId is required")
			return
		}
		period, err := securityEvents.GetPeriod(r.Context(), reqID)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusNotFound, "attack not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to load attack")
			return
		}
		viewer := viewerScopeFromContext(r.Context())
		serverID := int64(0)
		if period.ServerID != nil {
			serverID = *period.ServerID
		}
		if serverID > 0 && !viewer.canSeeServer(serverID) {
			writeError(w, http.StatusNotFound, "attack not found")
			return
		}

		now := time.Now().UTC()
		start, end := attackLiveWindow(period)
		drops := loadDropSeries(r.Context(), l4Stats, start, end, store.TrafficScope{ServerID: serverID})

		response := attackConsoleResponse{
			Attack:      period,
			ServerTime:  now.Format(time.RFC3339),
			WindowStart: start.Format(time.RFC3339),
			WindowEnd:   end.Format(time.RFC3339),
			Drops:       drops,
			Protection:  latestProtection(period),
			Sources:     []attackSource{},
			SpartaLog:   []attackLogLine{},
		}
		if blocked, err := securityEvents.ListBlockedSources(r.Context(), serverID, reqID); err == nil {
			response.Sources, response.AttackTypes, response.ActiveCount = buildAttackSources(blocked, now)
			response.SourceCount = len(response.Sources)
		}

		windowClosed := period.Status != "ongoing" && end.Add(spartaFlushLag).Before(now)
		if lines, ok := cachedSpartaLines(reqID, now); ok && windowClosed {
			response.SpartaLog = lines
		} else if serverID > 0 {
			viewCtx, cancelView := context.WithTimeout(r.Context(), 3*time.Second)
			view, viewErr := servers.GetView(viewCtx, serverID)
			cancelView()
			if viewErr != nil {
				response.SpartaError = "edge connection is unavailable"
			} else {
				logCtx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
				lines, logErr := remotesvc.ServiceJournalRange(logCtx, sshTargetFromView(view), "sparta", start, end.Add(spartaFlushLag), spartaCounterMatch, spartaLogLineLimit)
				cancel()
				if logErr != nil {
					response.SpartaError = "Sparta log is unavailable"
				} else {
					response.SpartaLog = toAttackLogLines(lines, start, end)
					if windowClosed {
						storeSpartaLines(reqID, response.SpartaLog, now)
					}
				}
			}
		}

		writeJSON(w, http.StatusOK, response)
	}
}

func buildAttackSources(blocked []store.BlockedSource, now time.Time) ([]attackSource, []attackTypeCount, int) {
	sources := make([]attackSource, 0, len(blocked))
	counts := map[string]int{}
	active := 0
	for _, item := range blocked {
		ttl := parseBlockTTL(item.TTL)
		releases := item.LastBlockedAt.Add(ttl)
		label := attackTypeLabel(item.AttackType)
		if label != "" {
			counts[label]++
		}
		source := attackSource{
			IP:             item.IP,
			AttackType:     label,
			FirstBlockedAt: item.FirstBlocked.Format(time.RFC3339),
			LastBlockedAt:  item.LastBlockedAt.Format(time.RFC3339),
			ReleasesAt:     releases.Format(time.RFC3339),
			Blocks:         item.Blocks,
			Active:         releases.After(now),
		}
		if source.Active {
			active++
		}
		sources = append(sources, source)
	}
	sort.SliceStable(sources, func(i, j int) bool {
		if sources[i].Active != sources[j].Active {
			return sources[i].Active
		}
		return sources[i].LastBlockedAt > sources[j].LastBlockedAt
	})
	types := make([]attackTypeCount, 0, len(counts))
	for label, count := range counts {
		types = append(types, attackTypeCount{Type: label, Count: count})
	}
	sort.Slice(types, func(i, j int) bool { return types[i].Count > types[j].Count })
	return sources, types, active
}

func parseBlockTTL(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultBlockTTL
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
		return parsed
	}
	return defaultBlockTTL
}

var spartaStamp = regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\]\s*`)

// toAttackLogLines prefers Sparta's own per-second stamp, which is edge wall-clock
// time, aligned to UTC against the journal time. The journal time alone lags
// because Sparta's output is flushed in batches.
func toAttackLogLines(lines []remotesvc.JournalLine, start, end time.Time) []attackLogLine {
	out := make([]attackLogLine, 0, len(lines))
	for _, line := range lines {
		at := line.Time
		text := line.Message
		if match := spartaStamp.FindStringSubmatch(text); match != nil {
			if wall, err := time.ParseInLocation("2006-01-02 15:04:05", strings.Replace(match[1], "T", " ", 1), time.UTC); err == nil {
				at = alignEdgeLocalTime(wall, line.Time)
			}
			text = text[len(match[0]):]
		}
		if at.Before(start) || at.After(end) {
			continue
		}
		out = append(out, attackLogLine{Time: at.Format(time.RFC3339), Text: strings.TrimSpace(text)})
	}
	return out
}

func cachedSpartaLines(reqID string, now time.Time) ([]attackLogLine, bool) {
	spartaLogCacheMu.Lock()
	defer spartaLogCacheMu.Unlock()
	entry, ok := spartaLogCache[reqID]
	if !ok || now.After(entry.expires) {
		delete(spartaLogCache, reqID)
		return nil, false
	}
	return entry.lines, true
}

func storeSpartaLines(reqID string, lines []attackLogLine, now time.Time) {
	spartaLogCacheMu.Lock()
	defer spartaLogCacheMu.Unlock()
	for key, entry := range spartaLogCache {
		if now.After(entry.expires) {
			delete(spartaLogCache, key)
		}
	}
	spartaLogCache[reqID] = cachedSpartaLog{lines: lines, expires: now.Add(spartaLogCacheTTL)}
}

const attackWindowPadding = 5 * time.Minute

func attackLiveWindow(period store.SecurityEventPeriod) (time.Time, time.Time) {
	now := time.Now().UTC()
	start := now.Add(-15 * time.Minute)
	if started, ok := parseConsoleTime(period.StartedAt); ok {
		start = started.Add(-attackWindowPadding)
	}
	end := now
	if period.Status != "ongoing" {
		stopped := period.EndedAt
		if strings.TrimSpace(stopped) == "" {
			stopped = period.CreatedAt
		}
		if parsed, ok := parseConsoleTime(stopped); ok && parsed.Add(attackWindowPadding).Before(now) {
			end = parsed.Add(attackWindowPadding)
		}
	}
	if !start.Before(end) {
		start = end.Add(-15 * time.Minute)
	}
	return start, end
}

func loadDropSeries(ctx context.Context, l4Stats store.L4AttackStatsStore, start, end time.Time, scope store.TrafficScope) []attackDropPoint {
	dropByTime := map[string]*attackDropPoint{}
	if l4Stats != nil && scope.ServerID > 0 {
		if series, err := l4Stats.ListTrafficSeries(ctx, start, end, scope); err == nil {
			for _, item := range series {
				if item.Timestamp == "" {
					continue
				}
				point, ok := dropByTime[item.Timestamp]
				if !ok {
					point = &attackDropPoint{Timestamp: item.Timestamp}
					dropByTime[item.Timestamp] = point
				}
				point.Blocked += item.BlockedTraffic
				point.Allowed += item.AllowedTraffic
			}
		}
	}

	drops := make([]attackDropPoint, 0, len(dropByTime))
	for _, point := range dropByTime {
		drops = append(drops, *point)
	}
	sort.Slice(drops, func(i, j int) bool { return drops[i].Timestamp < drops[j].Timestamp })
	return drops
}

func latestProtection(period store.SecurityEventPeriod) string {
	latest := ""
	for _, event := range period.Events {
		if event.Command != "report_protection" || strings.TrimSpace(event.Data) == "" {
			continue
		}
		latest = event.Data
	}
	return latest
}

func attackTypeLabel(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	tokens := map[string]bool{}
	for _, token := range strings.FieldsFunc(strings.ToUpper(raw), func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	}) {
		tokens[token] = true
	}
	switch {
	case tokens["SOCKET"], tokens["XMAS"], tokens["NULL"], tokens["FIN"]:
		return "SOCKET"
	case tokens["STOMP"], tokens["PSH"]:
		return "STOMP"
	case tokens["HANDSHAKE"]:
		return "HANDSHAKE"
	case tokens["SYN"]:
		return "TCP SYN"
	case tokens["RST"]:
		return "TCP RST"
	case tokens["ACK"]:
		return "TCP ACK"
	case tokens["UDP"]:
		return "UDP"
	case tokens["ICMP"]:
		return "ICMP"
	case tokens["GRE"]:
		return "GRE"
	default:
		return strings.TrimPrefix(raw, "EVENT_")
	}
}

func parseConsoleTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}
