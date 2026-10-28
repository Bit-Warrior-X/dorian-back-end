package remotesvc

import (
	"context"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	athensAccessLogDir = "/usr/local/share/dorian/athens/nginx/logs/access"
	spartaHourlyLogDir = "/usr/local/share/dorian/sparta/logs"
)

var (
	athensHourlyName = regexp.MustCompile(`^access-(\d{4}-\d{2}-\d{2}T\d{2})\.ndjson$`)
	spartaHourlyName = regexp.MustCompile(`^sparta-(\d{8})-(\d{2})\.log$`)
	spartaAttackName = regexp.MustCompile(`(?i)^\d{8}-\d{6}-req_\d+\.log$`)
)

// EdgeHourlyLogFile is one retained hourly (or attack) log file on an edge.
type EdgeHourlyLogFile struct {
	Layer     string    `json:"layer"` // l4 | l7
	Kind      string    `json:"kind"`  // hourly | attack | latest
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	SizeBytes int64     `json:"sizeBytes"`
	Hour      string    `json:"hour,omitempty"` // UTC-ish wall label YYYY-MM-DDTHH
	ModTime   time.Time `json:"modTime,omitempty"`
}

// EdgeHourlyLogPage is a slice of lines from an allowlisted edge log file.
type EdgeHourlyLogPage struct {
	Path    string   `json:"path"`
	Name    string   `json:"name"`
	Total   int      `json:"total"`
	Offset  int      `json:"offset"`
	Limit   int      `json:"limit"`
	HasMore bool     `json:"hasMore"`
	Lines   []string `json:"lines"`
}

// ListEdgeHourlyLogs lists L4/L7 retained log files on the edge (newest first).
// layer: l4 | l7 | all
func ListEdgeHourlyLogs(ctx context.Context, target SSHTarget, layer string) ([]EdgeHourlyLogFile, error) {
	layer = strings.ToLower(strings.TrimSpace(layer))
	if layer == "" {
		layer = "all"
	}
	switch layer {
	case "l4", "l7", "all":
	default:
		return nil, fmt.Errorf("layer must be l4, l7, or all")
	}

	client, err := dialSSH(ctx, target)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	parts := make([]string, 0, 3)
	if layer == "l7" || layer == "all" {
		parts = append(parts,
			fmt.Sprintf(
				`find %s -maxdepth 1 -type f -name 'access-*.ndjson' ! -name '.*' -printf 'l7\thourly\t%%s\t%%TY-%%Tm-%%TdT%%TH:%%TM:%%TS\t%%p\n' 2>/dev/null`,
				athensAccessLogDir,
			),
		)
	}
	if layer == "l4" || layer == "all" {
		parts = append(parts,
			fmt.Sprintf(
				`find %s -maxdepth 1 -type f -name 'sparta-*.log' -printf 'l4\thourly\t%%s\t%%TY-%%Tm-%%TdT%%TH:%%TM:%%TS\t%%p\n' 2>/dev/null`,
				spartaHourlyLogDir,
			),
			fmt.Sprintf(
				`find %s/attacks -maxdepth 1 -type f -name '*-req_*.log' -printf 'l4\tattack\t%%s\t%%TY-%%Tm-%%TdT%%TH:%%TM:%%TS\t%%p\n' 2>/dev/null`,
				spartaHourlyLogDir,
			),
		)
	}
	script := fmt.Sprintf(`timeout 20 sh -c %q`, strings.Join(parts, "; "))
	out, err := runRemoteScript(client, script)
	body := strings.TrimSpace(string(out))
	if err != nil && body == "" {
		return nil, err
	}
	return parseEdgeHourlyLogListing(body), nil
}

func parseEdgeHourlyLogListing(raw string) []EdgeHourlyLogFile {
	lines := strings.Split(raw, "\n")
	out := make([]EdgeHourlyLogFile, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 5)
		if len(parts) < 5 {
			continue
		}
		size, _ := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		mod := parseEdgeListingModTime(parts[3])
		filePath := strings.TrimSpace(parts[4])
		if !AllowedEdgeLogPath(filePath) {
			continue
		}
		name := path.Base(filePath)
		item := EdgeHourlyLogFile{
			Layer:     strings.ToLower(strings.TrimSpace(parts[0])),
			Kind:      strings.ToLower(strings.TrimSpace(parts[1])),
			Name:      name,
			Path:      filePath,
			SizeBytes: size,
			ModTime:   mod,
			Hour:      hourLabelFromLogName(name),
		}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].ModTime.Equal(out[j].ModTime) {
			return out[i].ModTime.After(out[j].ModTime)
		}
		return out[i].SizeBytes > out[j].SizeBytes
	})
	return out
}

func parseEdgeListingModTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	// find -printf %TY-%Tm-%TdT%TH:%TM:%TS may include fractional seconds.
	if dot := strings.IndexByte(raw, '.'); dot > 0 {
		raw = raw[:dot]
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04:05", raw, time.UTC); err == nil {
		return t
	}
	return time.Time{}
}

func hourLabelFromLogName(name string) string {
	if match := athensHourlyName.FindStringSubmatch(name); match != nil {
		return match[1]
	}
	if match := spartaHourlyName.FindStringSubmatch(name); match != nil {
		day := match[1]
		if len(day) == 8 {
			return fmt.Sprintf("%s-%s-%sT%s", day[0:4], day[4:6], day[6:8], match[2])
		}
	}
	return ""
}

// AllowedEdgeLogPath reports whether path is under the L4/L7 log allowlist.
func AllowedEdgeLogPath(filePath string) bool {
	filePath = path.Clean(strings.TrimSpace(filePath))
	if filePath == "" || strings.Contains(filePath, "..") {
		return false
	}
	name := path.Base(filePath)
	switch {
	case strings.HasPrefix(filePath, athensAccessLogDir+"/"):
		return athensHourlyName.MatchString(name)
	case strings.HasPrefix(filePath, spartaHourlyLogDir+"/attacks/"):
		return spartaAttackName.MatchString(name)
	case strings.HasPrefix(filePath, spartaHourlyLogDir+"/"):
		if name == "latest.log" {
			return true
		}
		return spartaHourlyName.MatchString(name)
	default:
		return false
	}
}

// ReadEdgeHourlyLogPage returns limit lines from offset (0-based) of an allowlisted file.
func ReadEdgeHourlyLogPage(ctx context.Context, target SSHTarget, filePath string, offset, limit int, skipTotal bool) (EdgeHourlyLogPage, error) {
	filePath = path.Clean(strings.TrimSpace(filePath))
	if !AllowedEdgeLogPath(filePath) {
		return EdgeHourlyLogPage{}, fmt.Errorf("path outside allowed log directories")
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	client, err := dialSSH(ctx, target)
	if err != nil {
		return EdgeHourlyLogPage{}, err
	}
	defer client.Close()

	startLine := offset + 1
	endLine := offset + limit
	totalFlag := "1"
	if skipTotal {
		totalFlag = "0"
	}
	script := fmt.Sprintf(
		`timeout 25 sh -c 'f=%q; [ -f "$f" ] || exit 0; `+
			`echo "FILE $f"; `+
			`if [ %s = 1 ]; then echo "TOTAL $(wc -l < "$f")"; else echo "TOTAL 0"; fi; `+
			`sed -n "%d,%dp" -- "$f"'`,
		filePath, totalFlag, startLine, endLine,
	)
	out, err := runRemoteScript(client, script)
	body := string(out)
	if err != nil && strings.TrimSpace(body) == "" {
		return EdgeHourlyLogPage{}, err
	}
	return parseEdgeHourlyLogPage(body, offset, limit), nil
}

func parseEdgeHourlyLogPage(raw string, offset, limit int) EdgeHourlyLogPage {
	page := EdgeHourlyLogPage{
		Offset: offset,
		Limit:  limit,
		Lines:  make([]string, 0, limit),
	}
	lines := strings.Split(raw, "\n")
	// Drop a single trailing empty split from a final newline so totals match wc -l.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "FILE ") {
			page.Path = strings.TrimSpace(strings.TrimPrefix(line, "FILE "))
			page.Name = path.Base(page.Path)
			continue
		}
		if strings.HasPrefix(line, "TOTAL ") {
			if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "TOTAL "))); err == nil {
				page.Total = n
			}
			continue
		}
		page.Lines = append(page.Lines, line)
	}
	if page.Total > 0 {
		page.HasMore = offset+len(page.Lines) < page.Total
	} else {
		page.HasMore = len(page.Lines) >= limit
	}
	return page
}

// StreamEdgeHourlyLog copies an allowlisted edge log file to w.
func StreamEdgeHourlyLog(ctx context.Context, target SSHTarget, filePath string, w io.Writer) error {
	filePath = path.Clean(strings.TrimSpace(filePath))
	if !AllowedEdgeLogPath(filePath) {
		return fmt.Errorf("path outside allowed log directories")
	}
	if strings.Contains(filePath, "'") || strings.Contains(filePath, "\n") {
		return fmt.Errorf("invalid log path")
	}
	client, err := dialSSH(ctx, target)
	if err != nil {
		return err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("ssh stdout: %w", err)
	}
	script := fmt.Sprintf(`timeout 900 cat -- %q`, filePath)
	if err := session.Start(script); err != nil {
		return fmt.Errorf("ssh start: %w", err)
	}
	if _, err := io.Copy(w, stdout); err != nil {
		_ = session.Wait()
		return err
	}
	if err := session.Wait(); err != nil {
		return fmt.Errorf("ssh wait: %w", err)
	}
	return nil
}

// StatEdgeHourlyLog returns size for an allowlisted path (0 if missing).
func StatEdgeHourlyLog(ctx context.Context, target SSHTarget, filePath string) (int64, error) {
	filePath = path.Clean(strings.TrimSpace(filePath))
	if !AllowedEdgeLogPath(filePath) {
		return 0, fmt.Errorf("path outside allowed log directories")
	}
	client, err := dialSSH(ctx, target)
	if err != nil {
		return 0, err
	}
	defer client.Close()
	script := fmt.Sprintf(`timeout 8 sh -c 'f=%q; [ -f "$f" ] || exit 0; wc -c < "$f"'`, filePath)
	out, err := runRemoteScript(client, script)
	body := strings.TrimSpace(string(out))
	if err != nil && body == "" {
		return 0, err
	}
	if body == "" {
		return 0, nil
	}
	n, parseErr := strconv.ParseInt(body, 10, 64)
	if parseErr != nil {
		return 0, parseErr
	}
	return n, nil
}
