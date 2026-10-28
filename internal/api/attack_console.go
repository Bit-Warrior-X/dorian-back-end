package api

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	Type      string `json:"type"`
	Count     int    `json:"count"`
	StartedAt string `json:"startedAt,omitempty"`
	EndedAt   string `json:"endedAt,omitempty"`
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
	defaultBlockTTL          = 60 * time.Second
	spartaCounterMatch       = `(SYN|ACK|PSH|RST|FIN|UDP|ICMP|GRE|STOMP|HANDSHAKE)[A-Z+]* *: *[0-9]`
	spartaConsolePageDefault = 24
	spartaConsolePageMax     = 80
	spartaFlushLag           = time.Minute
	attackConsoleSourceLimit = 25
	attackConsoleSourceMax   = 100
	attackConsoleEventLimit  = 40
	attackConsoleDropLimit   = 720
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
		drops := downsampleDropSeries(
			loadDropSeries(r.Context(), l4Stats, start, end, store.TrafficScope{ServerID: serverID}),
			attackConsoleDropLimit,
		)
		if n := len(period.Events); n > attackConsoleEventLimit {
			period.Events = append([]store.SecurityEvent(nil), period.Events[n-attackConsoleEventLimit:]...)
		}

		response := attackConsoleResponse{
			Attack:      period,
			ServerTime:  now.Format(time.RFC3339),
			WindowStart: start.Format(time.RFC3339),
			WindowEnd:   end.Format(time.RFC3339),
			Drops:       drops,
			Protection:  latestProtection(period),
			Sources:     []attackSource{},
			SpartaLog:   []attackLogLine{},
			SourceCount: period.IPCount,
			ActiveCount: period.ActiveIPCount,
			AttackTypes: attackTypesFromVectors(period.Vectors),
		}
		if len(response.AttackTypes) == 0 {
			response.AttackTypes = []attackTypeCount{}
		}
		response.AttackTypes = mergeAttackTypesWithProtection(response.AttackTypes, period)
		response.Attack.Vectors = toPeriodVectors(response.AttackTypes)
		if title := multiVectorTitle(response.AttackTypes); title != "" {
			response.Attack.Title = title
		}

		writeJSON(w, http.StatusOK, response)
	}
}

type attackSourcesResponse struct {
	ReqID       string         `json:"reqId"`
	Sources     []attackSource `json:"sources"`
	Offset      int            `json:"offset"`
	Limit       int            `json:"limit"`
	Next        int            `json:"next"`
	HasMore     bool           `json:"hasMore"`
	ActiveCount int            `json:"activeCount"`
	SourceCount int            `json:"sourceCount"`
	Query       string         `json:"query,omitempty"`
	ActiveOnly  bool           `json:"activeOnly"`
}

func attackConsoleSourcesHandler(securityEvents store.SecurityEventStore) http.HandlerFunc {
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
		offset, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("offset")))
		if offset < 0 {
			offset = 0
		}
		limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
		if limit <= 0 {
			limit = attackConsoleSourceLimit
		}
		if limit > attackConsoleSourceMax {
			limit = attackConsoleSourceMax
		}
		match := strings.TrimSpace(r.URL.Query().Get("q"))
		activeOnly := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("active")), "1") ||
			strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("active")), "true")

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
		blocked, listErr := securityEvents.ListBlockedSourcesPage(r.Context(), serverID, reqID, offset, limit, match, activeOnly)
		if listErr != nil {
			writeError(w, http.StatusInternalServerError, "failed to load sources")
			return
		}
		sources, _, _ := buildAttackSources(blocked, now)
		writeJSON(w, http.StatusOK, attackSourcesResponse{
			ReqID:       reqID,
			Sources:     sources,
			Offset:      offset,
			Limit:       limit,
			Next:        offset + len(sources),
			HasMore:     len(sources) >= limit,
			ActiveCount: period.ActiveIPCount,
			SourceCount: period.IPCount,
			Query:       match,
			ActiveOnly:  activeOnly,
		})
	}
}

func attackConsoleSpartaLogHandler(securityEvents store.SecurityEventStore, servers store.ServerStore) http.HandlerFunc {
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
		offset, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("offset")))
		if offset < 0 {
			offset = 0
		}
		limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
		if limit <= 0 {
			limit = spartaConsolePageDefault
		}
		if limit > spartaConsolePageMax {
			limit = spartaConsolePageMax
		}
		skipTotal := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("skipTotal")), "1") ||
			strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("skipTotal")), "true")

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

		empty := attackArchiveResponse{
			ReqID:    reqID,
			ServerID: serverID,
			Offset:   offset,
			Limit:    limit,
			Lines:    []attackArchiveLine{},
		}
		if serverID <= 0 {
			empty.Error = "no edge is linked to this attack"
			writeJSON(w, http.StatusOK, empty)
			return
		}

		viewCtx, cancelView := context.WithTimeout(r.Context(), 3*time.Second)
		view, viewErr := servers.GetView(viewCtx, serverID)
		cancelView()
		if viewErr != nil {
			empty.Error = "edge connection is unavailable"
			writeJSON(w, http.StatusOK, empty)
			return
		}

		start, end := attackLiveWindow(period)
		target := sshTargetFromView(view)
		logCtx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		// offset skips newest matching lines so the console can open on the tail
		// and load earlier counters as the user scrolls up.
		page, logErr := remotesvc.ReadSpartaAttackArchiveCounters(logCtx, target, reqID, spartaCounterMatch, offset, limit, skipTotal)
		cancel()
		if logErr != nil {
			empty.Error = "Sparta log is unavailable"
			writeJSON(w, http.StatusOK, empty)
			return
		}

		if page.File != "" {
			if len(page.Lines) > limit {
				page.Lines = page.Lines[:limit]
			}
			rawCount := len(page.Lines)
			// Archive stamps are edge wall-clock, not a UTC epoch. Drop any time
			// the pager copied from the stamp so timezone alignment uses the
			// attack window instead of treating local time as UTC.
			for i := range page.Lines {
				page.Lines[i].Time = time.Time{}
			}
			until := end.Add(spartaFlushLag)
			// The archive file is already scoped to this attack. Keep every
			// counter line even when DB window/timezone alignment disagrees.
			converted := convertAttackLogLines(page.Lines, start, until, page.EdgeStart, false)
			converted = filterCounterArchiveLines(converted)
			if len(converted) > limit {
				converted = converted[len(converted)-limit:]
			}
			next := offset + rawCount
			hasMore := page.HasMore
			if page.Total > 0 {
				hasMore = next < page.Total
			}
			writeJSON(w, http.StatusOK, attackArchiveResponse{
				ReqID:    reqID,
				ServerID: serverID,
				File:     page.File,
				FileName: pathBase(page.File),
				Total:    page.Total,
				Offset:   offset,
				Limit:    limit,
				Next:     next,
				HasMore:  hasMore,
				Lines:    toArchiveLines(converted),
			})
			return
		}

		if offset > 0 {
			writeJSON(w, http.StatusOK, empty)
			return
		}

		journalCtx, cancelJournal := context.WithTimeout(r.Context(), 8*time.Second)
		journal, journalErr := remotesvc.ServiceJournalRange(journalCtx, target, "sparta", start, end.Add(spartaFlushLag), spartaCounterMatch, limit)
		cancelJournal()
		if journalErr != nil {
			empty.Error = "Sparta log is unavailable"
			writeJSON(w, http.StatusOK, empty)
			return
		}
		converted := toAttackLogLines(journal, start, end.Add(spartaFlushLag), time.Time{})
		writeJSON(w, http.StatusOK, attackArchiveResponse{
			ReqID:    reqID,
			ServerID: serverID,
			Offset:   0,
			Limit:    limit,
			Next:     len(converted),
			HasMore:  false,
			Lines:    toArchiveLines(converted),
		})
	}
}

func pathBase(filePath string) string {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return ""
	}
	if i := strings.LastIndex(filePath, "/"); i >= 0 && i+1 < len(filePath) {
		return filePath[i+1:]
	}
	return filePath
}

func toArchiveLines(lines []attackLogLine) []attackArchiveLine {
	out := make([]attackArchiveLine, 0, len(lines))
	for _, line := range lines {
		out = append(out, attackArchiveLine{Time: line.Time, Text: line.Text})
	}
	return out
}

func buildAttackSources(blocked []store.BlockedSource, now time.Time) ([]attackSource, []attackTypeCount, int) {
	sources := make([]attackSource, 0, len(blocked))
	counts := map[string]int{}
	firstAt := map[string]time.Time{}
	lastAt := map[string]time.Time{}
	active := 0
	for _, item := range blocked {
		ttl := parseBlockTTL(item.TTL)
		releases := item.LastBlockedAt.Add(ttl)
		label := attackTypeLabel(item.AttackType)
		if label != "" {
			counts[label]++
			if item.FirstBlocked.After(time.Time{}) {
				if prev, ok := firstAt[label]; !ok || item.FirstBlocked.Before(prev) {
					firstAt[label] = item.FirstBlocked
				}
			}
			if item.LastBlockedAt.After(time.Time{}) {
				if prev, ok := lastAt[label]; !ok || item.LastBlockedAt.After(prev) {
					lastAt[label] = item.LastBlockedAt
				}
			}
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
		item := attackTypeCount{Type: label, Count: count}
		if at, ok := firstAt[label]; ok {
			item.StartedAt = at.UTC().Format(time.RFC3339)
		}
		if at, ok := lastAt[label]; ok {
			item.EndedAt = at.UTC().Format(time.RFC3339)
		}
		types = append(types, item)
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
// time, aligned to UTC. Live journal lines use the journal epoch as the alignment
// reference. Archive lines use edgeStart (file header/filename) vs the attack
// window start to recover a fixed timezone offset after journal retention is gone.
func toAttackLogLines(lines []remotesvc.JournalLine, start, end, edgeStart time.Time) []attackLogLine {
	return convertAttackLogLines(lines, start, end, edgeStart, true)
}

var (
	spartaCounterLine = regexp.MustCompile(`(?i)\b(?:SYN|ACK|PSH|RST|FIN|UDP|ICMP|GRE|STOMP|HANDSHAKE)[A-Z+]*\s*:\s*[0-9]`)
	spartaLooseCount  = regexp.MustCompile(`(?i)\b[A-Z][A-Z0-9+]*\s*:\s*[0-9]`)
)

func filterCounterArchiveLines(lines []attackLogLine) []attackLogLine {
	out := make([]attackLogLine, 0, len(lines))
	for _, line := range lines {
		if spartaCounterLine.MatchString(line.Text) {
			out = append(out, line)
		}
	}
	if len(out) > 0 {
		return out
	}
	// Raw-tail fallback may use a looser KEY: number shape.
	for _, line := range lines {
		text := strings.TrimSpace(line.Text)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if spartaLooseCount.MatchString(text) {
			out = append(out, line)
		}
	}
	return out
}

func convertAttackLogLines(lines []remotesvc.JournalLine, start, end, edgeStart time.Time, dropOutside bool) []attackLogLine {
	periodStart := start
	if !start.IsZero() {
		periodStart = start.Add(attackWindowPadding)
	}
	var archiveOffset time.Duration
	haveArchiveOffset := false
	if !edgeStart.IsZero() && !periodStart.IsZero() {
		archiveOffset = periodStart.Sub(edgeStart).Round(time.Minute)
		haveArchiveOffset = true
	}

	out := make([]attackLogLine, 0, len(lines))
	for _, line := range lines {
		at := line.Time
		text := line.Message
		if match := spartaStamp.FindStringSubmatch(text); match != nil {
			if wall, err := time.ParseInLocation("2006-01-02 15:04:05", strings.Replace(match[1], "T", " ", 1), time.UTC); err == nil {
				// A stamp copied onto Time is wall-clock, not a journal epoch.
				// Only trust Time when it disagrees with the stamp.
				journalRef := !line.Time.IsZero() && line.Time.Year() >= 2000 && line.Time.Sub(wall).Abs() > time.Second
				switch {
				case journalRef:
					at = alignEdgeLocalTime(wall, line.Time)
				case haveArchiveOffset:
					at = wall.Add(archiveOffset)
				default:
					at = alignEdgeLocalTime(wall, time.Now().UTC())
				}
			}
			text = text[len(match[0]):]
		} else if at.IsZero() {
			continue
		}
		if dropOutside {
			if !start.IsZero() && at.Before(start) {
				continue
			}
			if !end.IsZero() && at.After(end) {
				continue
			}
		}
		out = append(out, attackLogLine{Time: at.Format(time.RFC3339), Text: strings.TrimSpace(text)})
	}
	return out
}

const attackWindowPadding = 5 * time.Minute

func attackTypesFromVectors(vectors []store.PeriodVector) []attackTypeCount {
	out := make([]attackTypeCount, 0, len(vectors))
	for _, item := range vectors {
		if strings.TrimSpace(item.Type) == "" {
			continue
		}
		out = append(out, attackTypeCount{Type: item.Type, Count: item.Count})
	}
	return out
}

func overlayAttackTypeWindows(types, fromBlocks []attackTypeCount) []attackTypeCount {
	if len(types) == 0 {
		return fromBlocks
	}
	windows := make(map[string]attackTypeCount, len(fromBlocks))
	for _, item := range fromBlocks {
		windows[item.Type] = item
	}
	for i := range types {
		if hit, ok := windows[types[i].Type]; ok {
			types[i].StartedAt = hit.StartedAt
			types[i].EndedAt = hit.EndedAt
		}
	}
	return types
}

func downsampleDropSeries(drops []attackDropPoint, max int) []attackDropPoint {
	n := len(drops)
	if max < 2 || n <= max {
		return drops
	}
	out := make([]attackDropPoint, 0, max)
	for i := 0; i < max-1; i++ {
		out = append(out, drops[(i*(n-1))/(max-1)])
	}
	out = append(out, drops[n-1])
	return out
}

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

// mergeAttackTypesWithProtection adds vectors that only appear as protection-mode
// START/END (e.g. RST with no report_block_ip rows) and attaches each vector's window.
func mergeAttackTypesWithProtection(fromBlocks []attackTypeCount, period store.SecurityEventPeriod) []attackTypeCount {
	byType := map[string]*attackTypeCount{}
	order := make([]string, 0, len(fromBlocks)+4)
	ensure := func(label string) *attackTypeCount {
		if label == "" {
			return nil
		}
		if item, ok := byType[label]; ok {
			return item
		}
		item := &attackTypeCount{Type: label}
		byType[label] = item
		order = append(order, label)
		return item
	}
	for _, item := range fromBlocks {
		entry := ensure(item.Type)
		if entry == nil {
			continue
		}
		entry.Count = item.Count
		entry.StartedAt = item.StartedAt
		entry.EndedAt = item.EndedAt
	}

	for _, event := range period.Events {
		if !strings.EqualFold(event.Command, "report_protection") {
			continue
		}
		data := strings.ToUpper(strings.TrimSpace(event.Data))
		if data == "" {
			continue
		}
		label := attackTypeLabel(data)
		entry := ensure(label)
		if entry == nil {
			continue
		}
		at := strings.TrimSpace(event.CreatedAt)
		if strings.Contains(data, "START") {
			if entry.StartedAt == "" || (at != "" && at < entry.StartedAt) {
				entry.StartedAt = at
			}
			continue
		}
		if strings.Contains(data, "END") {
			if entry.EndedAt == "" || (at != "" && at > entry.EndedAt) {
				entry.EndedAt = at
			}
		}
	}

	out := make([]attackTypeCount, 0, len(order))
	for _, label := range order {
		out = append(out, *byType[label])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func multiVectorTitle(types []attackTypeCount) string {
	labels := make([]string, 0, len(types))
	seen := map[string]struct{}{}
	for _, item := range types {
		label := strings.TrimSpace(item.Type)
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		labels = append(labels, label)
	}
	switch len(labels) {
	case 0:
		return ""
	case 1:
		return labels[0] + " flood"
	case 2:
		return labels[0] + " + " + labels[1] + " flood"
	default:
		return strings.Join(labels[:len(labels)-1], ", ") + " + " + labels[len(labels)-1] + " flood"
	}
}

func toPeriodVectors(types []attackTypeCount) []store.PeriodVector {
	out := make([]store.PeriodVector, 0, len(types))
	for _, item := range types {
		out = append(out, store.PeriodVector{Type: item.Type, Count: item.Count})
	}
	return out
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
