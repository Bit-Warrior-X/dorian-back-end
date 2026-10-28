package api

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

const (
	logExportMaxRows     = 100000
	logExportMaxDays     = 7
	logExportPageSize    = 20000
	logExportHTTPTimeout = 45 * time.Second
)

type logExportRequest struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	Type     string `json:"type"`
	Format   string `json:"format"`
	ServerID int64  `json:"serverId"`
	SiteID   int64  `json:"siteId"`
}

type logExportRow struct {
	Time          string  `json:"time"`
	ClientIP      string  `json:"clientIp"`
	Method        string  `json:"method"`
	Host          string  `json:"host"`
	Path          string  `json:"path"`
	Status        int     `json:"status"`
	Bytes         int64   `json:"bytes"`
	RequestTimeMs float64 `json:"requestTimeMs"`
	CacheStatus   string  `json:"cacheStatus"`
	UserAgent     string  `json:"userAgent"`
	Action        string  `json:"action,omitempty"`
	RuleType      string  `json:"ruleType,omitempty"`
	ServerID      int64   `json:"serverId,omitempty"`
	ServerName    string  `json:"serverName,omitempty"`
	SiteID        int64   `json:"siteId,omitempty"`
	LogKind       string  `json:"logKind"`
}

type athensAccessLogRecord struct {
	Time          string  `json:"time"`
	SiteID        int64   `json:"site_id"`
	ClientIP      string  `json:"client_ip"`
	Method        string  `json:"method"`
	Host          string  `json:"host"`
	URI           string  `json:"uri"`
	Status        int     `json:"status"`
	BytesSent     int64   `json:"bytes_sent"`
	RequestTimeMs float64 `json:"request_time_ms"`
	CacheStatus   *string `json:"cache_status"`
	UserAgent     *string `json:"user_agent"`
	Blocked       bool    `json:"blocked"`
	RuleType      *string `json:"rule_type"`
}

func analyticsLogsExportHandler(cfg config.Config, servers store.ServerStore, sites store.SiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var payload logExportRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		start, end, err := parseLogExportWindow(payload.Start, payload.End)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if end.Sub(start) > logExportMaxDays*24*time.Hour {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("date range cannot exceed %d days (Athens retention)", logExportMaxDays))
			return
		}
		logType := strings.ToLower(strings.TrimSpace(payload.Type))
		if logType == "" {
			logType = "access"
		}
		format := strings.ToLower(strings.TrimSpace(payload.Format))
		switch format {
		case "csv", "json", "txt":
		default:
			writeError(w, http.StatusBadRequest, "format must be csv, json, or txt")
			return
		}
		switch logType {
		case "access", "security", "all":
		case "error":
			writeError(w, http.StatusUnprocessableEntity, "Error log export is not available yet. Athens retains access and security request logs; use Access or Security.")
			return
		default:
			writeError(w, http.StatusBadRequest, "type must be access, security, error, or all")
			return
		}

		viewer := viewerScopeFromContext(r.Context())
		if payload.ServerID > 0 && !viewer.canSeeServer(payload.ServerID) {
			writeError(w, http.StatusNotFound, "server not found")
			return
		}
		if payload.SiteID > 0 {
			site, siteErr := sites.Get(r.Context(), payload.SiteID)
			if siteErr != nil || !viewer.canSeeSite(site) {
				writeError(w, http.StatusNotFound, "site not found")
				return
			}
		}

		list, err := servers.ListWithUsers(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load servers")
			return
		}
		list = viewer.filterServers(list)
		if payload.ServerID > 0 {
			filtered := make([]store.ServerView, 0, 1)
			for _, server := range list {
				if server.ID == payload.ServerID {
					filtered = append(filtered, server)
					break
				}
			}
			list = filtered
		}
		if len(list) == 0 {
			writeError(w, http.StatusBadRequest, "no edges available for export")
			return
		}

		metricsPort := strings.TrimSpace(cfg.MetricsPort)
		if metricsPort == "" {
			metricsPort = "9000"
		}

		kinds := []string{logType}
		if logType == "all" {
			kinds = []string{"access", "security"}
		}

		exportCtx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()

		rows := make([]logExportRow, 0, 4096)
		var warnings []string
		httpClient := &http.Client{Timeout: logExportHTTPTimeout}

		for _, server := range list {
			ip := strings.TrimSpace(server.IP)
			if ip == "" {
				continue
			}
			for _, kind := range kinds {
				page, warn, fetchErr := fetchAthensAccessLogPages(exportCtx, httpClient, ip, metricsPort, start, end, payload.SiteID, kind, logExportMaxRows-len(rows))
				if warn != "" {
					warnings = append(warnings, fmt.Sprintf("%s: %s", server.Name, warn))
				}
				if fetchErr != nil {
					warnings = append(warnings, fmt.Sprintf("%s (%s): %v", server.Name, kind, fetchErr))
					continue
				}
				for _, rec := range page {
					rows = append(rows, athensRecordToExportRow(rec, server, kind))
					if len(rows) >= logExportMaxRows {
						warnings = append(warnings, fmt.Sprintf("truncated at %d rows", logExportMaxRows))
						break
					}
				}
				if len(rows) >= logExportMaxRows {
					break
				}
			}
			if len(rows) >= logExportMaxRows {
				break
			}
		}

		body, err := serializeLogExport(rows, format)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to serialize export")
			return
		}
		fileName := fmt.Sprintf(
			"dorian-%s-logs-%s_%s.%s",
			logType,
			sanitizeExportStamp(payload.Start),
			sanitizeExportStamp(payload.End),
			format,
		)
		w.Header().Set("Content-Type", logExportContentType(format))
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName))
		w.Header().Set("X-Export-Rows", strconv.Itoa(len(rows)))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if len(warnings) > 0 {
			// Keep header compact for proxies.
			note := strings.Join(warnings, "; ")
			if len(note) > 500 {
				note = note[:500] + "…"
			}
			w.Header().Set("X-Export-Warnings", note)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

func parseLogExportWindow(startRaw, endRaw string) (time.Time, time.Time, error) {
	startRaw = strings.TrimSpace(startRaw)
	endRaw = strings.TrimSpace(endRaw)
	if startRaw == "" || endRaw == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("start and end are required")
	}
	start, startDateOnly, err := parseLogExportInstant(startRaw)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid start: %w", err)
	}
	end, endDateOnly, err := parseLogExportInstant(endRaw)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid end: %w", err)
	}
	if end.Before(start) {
		return time.Time{}, time.Time{}, fmt.Errorf("start must be on or before end")
	}
	// Athens uses [start, end). Date-only end is inclusive of that calendar day;
	// datetime end is inclusive through that minute.
	switch {
	case endDateOnly:
		end = end.Add(24 * time.Hour)
	case startDateOnly && !endDateOnly:
		// mixed: keep datetime end exclusive by adding one minute so the picked
		// minute is included.
		end = end.Add(time.Minute)
	default:
		if !endDateOnly {
			end = end.Add(time.Minute)
		}
	}
	return start.UTC(), end.UTC(), nil
}

func parseLogExportInstant(raw string) (time.Time, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false, fmt.Errorf("use YYYY-MM-DD or YYYY-MM-DD HH:mm")
	}
	// UI sends Date.toISOString() (RFC3339 with fractional seconds). Parse that
	// before any T→space rewrite, which would break the ISO form.
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed, false, nil
		}
	}
	normalized := strings.Replace(raw, "T", " ", 1)
	layouts := []struct {
		layout   string
		dateOnly bool
	}{
		{"2006-01-02 15:04:05", false},
		{"2006-01-02 15:04", false},
		{"2006-01-02", true},
	}
	for _, item := range layouts {
		if parsed, err := time.ParseInLocation(item.layout, normalized, time.Local); err == nil {
			return parsed, item.dateOnly, nil
		}
	}
	return time.Time{}, false, fmt.Errorf("use YYYY-MM-DD or YYYY-MM-DD HH:mm")
}

func fetchAthensAccessLogPages(
	ctx context.Context,
	client *http.Client,
	serverIP, metricsPort string,
	start, end time.Time,
	siteID int64,
	logType string,
	remaining int,
) ([]athensAccessLogRecord, string, error) {
	if remaining <= 0 {
		return nil, "", nil
	}
	out := make([]athensAccessLogRecord, 0, 1024)
	cursor := ""
	var retentionNote string
	for remaining > 0 {
		limit := logExportPageSize
		if limit > remaining {
			limit = remaining
		}
		page, next, rangeNote, err := fetchAthensAccessLogPage(ctx, client, serverIP, metricsPort, start, end, siteID, logType, limit, cursor)
		if err != nil {
			return out, retentionNote, err
		}
		if rangeNote != "" && retentionNote == "" {
			retentionNote = rangeNote
		}
		out = append(out, page...)
		remaining -= len(page)
		if next == "" || len(page) == 0 {
			break
		}
		cursor = next
	}
	return out, retentionNote, nil
}

func fetchAthensAccessLogPage(
	ctx context.Context,
	client *http.Client,
	serverIP, metricsPort string,
	start, end time.Time,
	siteID int64,
	logType string,
	limit int,
	cursor string,
) ([]athensAccessLogRecord, string, string, error) {
	q := fmt.Sprintf("type=%s&start=%d&end=%d&limit=%d", logType, start.Unix(), end.Unix(), limit)
	if siteID > 0 {
		q += fmt.Sprintf("&site_id=%d", siteID)
	}
	if cursor != "" {
		q += "&cursor=" + cursor
	}
	url := fmt.Sprintf("http://%s:%s/access_logs?%s", serverIP, metricsPort, q)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		var payload struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &payload)
		msg := strings.TrimSpace(payload.Error)
		if msg == "" {
			msg = "requested range is older than retained logs"
		}
		return nil, "", msg, nil
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = fmt.Sprintf("athens returned status %d", resp.StatusCode)
		}
		return nil, "", "", fmt.Errorf("%s", msg)
	}
	records := make([]athensAccessLogRecord, 0, 256)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	// Large NDJSON lines (user-agent / URI) can exceed default 64KiB.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec athensAccessLogRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		records = append(records, rec)
	}
	next := strings.TrimSpace(resp.Header.Get("X-Next-Cursor"))
	return records, next, "", scanner.Err()
}

func athensRecordToExportRow(rec athensAccessLogRecord, server store.ServerView, kind string) logExportRow {
	row := logExportRow{
		Time:          strings.TrimSpace(rec.Time),
		ClientIP:      strings.TrimSpace(rec.ClientIP),
		Method:        strings.TrimSpace(rec.Method),
		Host:          strings.TrimSpace(rec.Host),
		Path:          strings.TrimSpace(rec.URI),
		Status:        rec.Status,
		Bytes:         rec.BytesSent,
		RequestTimeMs: rec.RequestTimeMs,
		ServerID:      server.ID,
		ServerName:    server.Name,
		SiteID:        rec.SiteID,
		LogKind:       kind,
	}
	if rec.CacheStatus != nil {
		row.CacheStatus = *rec.CacheStatus
	}
	if rec.UserAgent != nil {
		row.UserAgent = *rec.UserAgent
	}
	if rec.Blocked || kind == "security" {
		row.Action = "block"
	} else {
		row.Action = "allow"
	}
	if rec.RuleType != nil {
		row.RuleType = *rec.RuleType
	}
	return row
}

func serializeLogExport(rows []logExportRow, format string) ([]byte, error) {
	switch format {
	case "json":
		if rows == nil {
			rows = []logExportRow{}
		}
		return json.MarshalIndent(rows, "", "  ")
	case "txt":
		var b strings.Builder
		for _, row := range rows {
			ua := row.UserAgent
			if ua == "" {
				ua = "-"
			}
			fmt.Fprintf(&b, `%s - - [%s] "%s %s HTTP/1.1" %d %d "%s" "%s" edge=%s kind=%s`,
				dash(row.ClientIP),
				row.Time,
				dash(row.Method),
				dash(row.Path),
				row.Status,
				row.Bytes,
				ua,
				dash(row.Host),
				dash(row.ServerName),
				row.LogKind,
			)
			if row.Action != "" {
				fmt.Fprintf(&b, " action=%s", row.Action)
			}
			if row.RuleType != "" {
				fmt.Fprintf(&b, " rule=%s", row.RuleType)
			}
			b.WriteByte('\n')
		}
		return []byte(b.String()), nil
	default: // csv
		var b strings.Builder
		cw := csv.NewWriter(&b)
		header := []string{
			"time", "clientIp", "method", "host", "path", "status", "bytes",
			"requestTimeMs", "cacheStatus", "userAgent", "action", "ruleType",
			"serverId", "serverName", "siteId", "logKind",
		}
		if err := cw.Write(header); err != nil {
			return nil, err
		}
		for _, row := range rows {
			if err := cw.Write([]string{
				row.Time,
				row.ClientIP,
				row.Method,
				row.Host,
				row.Path,
				strconv.Itoa(row.Status),
				strconv.FormatInt(row.Bytes, 10),
				strconv.FormatFloat(row.RequestTimeMs, 'f', 3, 64),
				row.CacheStatus,
				row.UserAgent,
				row.Action,
				row.RuleType,
				strconv.FormatInt(row.ServerID, 10),
				row.ServerName,
				strconv.FormatInt(row.SiteID, 10),
				row.LogKind,
			}); err != nil {
				return nil, err
			}
		}
		cw.Flush()
		return []byte(b.String()), cw.Error()
	}
}

func logExportContentType(format string) string {
	switch format {
	case "json":
		return "application/json; charset=utf-8"
	case "txt":
		return "text/plain; charset=utf-8"
	default:
		return "text/csv; charset=utf-8"
	}
}

func dash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func sanitizeExportStamp(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, ":", "")
	raw = strings.ReplaceAll(raw, " ", "_")
	raw = strings.ReplaceAll(raw, "T", "_")
	raw = strings.ReplaceAll(raw, "/", "-")
	if len(raw) > 32 {
		raw = raw[:32]
	}
	if raw == "" {
		return "range"
	}
	return raw
}
