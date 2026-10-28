package remotesvc

import (
	"context"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	spartaLogDir             = "/usr/local/share/dorian/sparta/logs"
	spartaLatestLogPath      = spartaLogDir + "/latest.log"
	spartaAttackLogDir       = spartaLogDir + "/attacks"
	spartaAttackLogDirLegacy = "/var/log/sparta/attacks"
)

var (
	spartaReqIDPattern    = regexp.MustCompile(`(?i)^(?:req_)?([0-9]{6,32})$`)
	spartaArchiveStarted  = regexp.MustCompile(`(?i)^ARCHIVE_STARTED\s+(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s*$`)
	spartaArchiveFileLine = regexp.MustCompile(`(?i)^ARCHIVE_FILE\s+(\S+)`)
	spartaArchiveFileTS   = regexp.MustCompile(`(\d{8})-(\d{6})-`)
	spartaArchiveTotal    = regexp.MustCompile(`(?i)^ARCHIVE_TOTAL\s+(\d+)\s*$`)
	spartaArchiveHasMore  = regexp.MustCompile(`(?i)^ARCHIVE_HAS_MORE\s+(\d+)\s*$`)
	spartaArchiveStamp    = regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\]\s*`)
)

// NormalizeSpartaReqID strips an optional req_ prefix and accepts only numeric ids.
func NormalizeSpartaReqID(reqID string) (string, error) {
	raw := strings.TrimSpace(reqID)
	match := spartaReqIDPattern.FindStringSubmatch(raw)
	if match == nil {
		return "", fmt.Errorf("invalid sparta req id")
	}
	return match[1], nil
}

// SpartaAttackArchive is the counter stream from a per-attack log file, plus the
// edge wall-clock start taken from the file header/filename (for timezone align).
type SpartaAttackArchive struct {
	Lines     []JournalLine
	EdgeStart time.Time // zero if unknown; naive wall-clock stored in UTC location
}

// ReadSpartaAttackArchive loads counter lines from Sparta's per-attack archive file
// on the edge: /usr/local/share/dorian/sparta/logs/attacks/YYYYMMDD-HHMMSS-req_<id>.log
//
// match is an extended regex applied on the edge (must not contain a single quote).
// Returns the newest matching lines up to maxLines. Missing files yield an empty
// archive without error so callers can fall back to journalctl.
func ReadSpartaAttackArchive(ctx context.Context, target SSHTarget, reqID, match string, maxLines int) (SpartaAttackArchive, error) {
	id, err := NormalizeSpartaReqID(reqID)
	if err != nil {
		return SpartaAttackArchive{}, err
	}
	if strings.Contains(match, "'") || strings.Contains(id, "'") {
		return SpartaAttackArchive{}, fmt.Errorf("invalid journal match")
	}
	if maxLines <= 0 || maxLines > 5000 {
		maxLines = 2000
	}

	client, err := dialSSH(ctx, target)
	if err != nil {
		return SpartaAttackArchive{}, err
	}
	defer client.Close()

	// Emit ARCHIVE_FILE / ARCHIVE_STARTED so timezone offset can be recovered even
	// when we only tail the newest counter lines of a huge file.
	script := fmt.Sprintf(
		`timeout 12 sh -c '%s; `+
			`[ -n "$f" ] && [ -f "$f" ] || exit 0; `+
			`echo "ARCHIVE_FILE $f"; `+
			`started=$(sed -n "s/^# started  *: *//p" "$f" | head -n 1); `+
			`echo "ARCHIVE_STARTED $started"; `+
			`grep -a -E '"'"'%s'"'"' -- "$f" | tail -n %d'`,
		spartaFindAttackArchiveShell(id), match, maxLines,
	)

	out, err := runRemoteScript(client, script)
	body := strings.TrimSpace(string(out))
	if err != nil && body == "" {
		return SpartaAttackArchive{}, err
	}
	return parseSpartaAttackArchive(body), nil
}

func parseSpartaAttackArchive(raw string) SpartaAttackArchive {
	lines := strings.Split(raw, "\n")
	out := SpartaAttackArchive{Lines: make([]JournalLine, 0, len(lines))}
	var fileStart time.Time
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if match := spartaArchiveStarted.FindStringSubmatch(line); match != nil {
			stamp := strings.TrimSpace(match[1])
			if stamp != "" {
				if wall, err := time.ParseInLocation("2006-01-02 15:04:05", strings.Replace(stamp, "T", " ", 1), time.UTC); err == nil {
					out.EdgeStart = wall
				}
			}
			continue
		}
		if match := spartaArchiveFileLine.FindStringSubmatch(line); match != nil {
			if ts := spartaArchiveFileTS.FindStringSubmatch(match[1]); ts != nil {
				stamp := ts[1] + ts[2]
				if wall, err := time.ParseInLocation("20060102150405", stamp, time.UTC); err == nil {
					fileStart = wall
				}
			}
			continue
		}
		// Leave Time zero: stamps are edge wall-clock and must be aligned later.
		out.Lines = append(out.Lines, JournalLine{Message: line})
	}
	if out.EdgeStart.IsZero() {
		out.EdgeStart = fileStart
	}
	return out
}

// SpartaAttackArchivePage is one slice of the raw per-attack archive (all line
// kinds: headers, DETECT, counters, DEBUG), for the full-log viewer.
type SpartaAttackArchivePage struct {
	File      string
	EdgeStart time.Time
	Total     int
	Offset    int
	Limit     int
	Lines     []JournalLine
	HasMore   bool
}

// ReadSpartaAttackArchiveCounters pages matching counter lines from the
// newest end of the per-attack archive. offset is how many newest matches to
// skip (0 = latest page). Missing files return an empty page without error.
func ReadSpartaAttackArchiveCounters(ctx context.Context, target SSHTarget, reqID, match string, offset, limit int, skipTotal bool) (SpartaAttackArchivePage, error) {
	id, err := NormalizeSpartaReqID(reqID)
	if err != nil {
		return SpartaAttackArchivePage{}, err
	}
	if strings.Contains(match, "'") || strings.Contains(id, "'") {
		return SpartaAttackArchivePage{}, fmt.Errorf("invalid journal match")
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 200 {
		limit = 80
	}

	client, err := dialSSH(ctx, target)
	if err != nil {
		return SpartaAttackArchivePage{}, err
	}
	defer client.Close()

	window := offset + limit
	totalFlag := "1"
	if skipTotal {
		totalFlag = "0"
	}
	// Prefer counter matches, then any KEY: digits lines, then a raw file tail.
	// Tail a window from the end, then keep only the older slice so pages do
	// not overlap the already-loaded newest lines.
	loose := `[A-Z][A-Z0-9+]* *: *[0-9]`
	script := fmt.Sprintf(
		`timeout 12 sh -c '%s; `+
			`[ -n "$f" ] && [ -f "$f" ] || exit 0; `+
			`echo "ARCHIVE_FILE $f"; `+
			`started=$(sed -n "s/^# started  *: *//p" "$f" | head -n 1); `+
			`echo "ARCHIVE_STARTED $started"; `+
			`if [ %s = 1 ]; then echo "ARCHIVE_TOTAL $(grep -ac -E '"'"'%s'"'"' -- "$f" || true)"; else echo "ARCHIVE_TOTAL 0"; fi; `+
			`matched=$(grep -a -E '"'"'%s'"'"' -- "$f" | tail -n %d); `+
			`if [ -z "$matched" ]; then matched=$(grep -a -E '"'"'%s'"'"' -- "$f" | tail -n %d); fi; `+
			`if [ -z "$matched" ]; then matched=$(tail -n %d -- "$f"); fi; `+
			`n=0; if [ -n "$matched" ]; then n=$(printf '"'"'%%s\n'"'"' "$matched" | grep -c "^" || true); fi; `+
			`if [ "$n" -ge %d ]; then echo "ARCHIVE_HAS_MORE 1"; else echo "ARCHIVE_HAS_MORE 0"; fi; `+
			`older=$((n-%d)); `+
			`if [ "$older" -gt 0 ]; then printf '"'"'%%s\n'"'"' "$matched" | head -n "$older"; fi'`,
		spartaFindAttackArchiveShell(id), totalFlag, match, match, window, loose, window, window, window, offset,
	)

	out, err := runRemoteScript(client, script)
	body := string(out)
	if err != nil && strings.TrimSpace(body) == "" {
		return SpartaAttackArchivePage{}, err
	}
	return parseSpartaAttackArchivePage(body, offset, limit), nil
}

// ReadSpartaAttackArchivePage reads limit lines from the archive starting at
// offset (0-based). When skipTotal is true the edge skips wc -l (caller already
// knows the length). Missing files return an empty page without error.
func ReadSpartaAttackArchivePage(ctx context.Context, target SSHTarget, reqID string, offset, limit int, skipTotal bool) (SpartaAttackArchivePage, error) {
	id, err := NormalizeSpartaReqID(reqID)
	if err != nil {
		return SpartaAttackArchivePage{}, err
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	client, err := dialSSH(ctx, target)
	if err != nil {
		return SpartaAttackArchivePage{}, err
	}
	defer client.Close()

	startLine := offset + 1
	endLine := offset + limit
	totalFlag := "1"
	if skipTotal {
		totalFlag = "0"
	}
	script := fmt.Sprintf(
		`timeout 20 sh -c '%s; `+
			`[ -n "$f" ] && [ -f "$f" ] || exit 0; `+
			`echo "ARCHIVE_FILE $f"; `+
			`started=$(sed -n "s/^# started  *: *//p" "$f" | head -n 1); `+
			`echo "ARCHIVE_STARTED $started"; `+
			`if [ %s = 1 ]; then echo "ARCHIVE_TOTAL $(wc -l < "$f")"; else echo "ARCHIVE_TOTAL 0"; fi; `+
			`sed -n "%d,%dp" -- "$f"'`,
		spartaFindAttackArchiveShell(id), totalFlag, startLine, endLine,
	)

	out, err := runRemoteScript(client, script)
	body := string(out)
	if err != nil && strings.TrimSpace(body) == "" {
		return SpartaAttackArchivePage{}, err
	}
	page := parseSpartaAttackArchivePage(body, offset, limit)
	return page, nil
}

func parseSpartaAttackArchivePage(raw string, offset, limit int) SpartaAttackArchivePage {
	page := SpartaAttackArchivePage{
		Offset: offset,
		Limit:  limit,
		Lines:  make([]JournalLine, 0, limit),
	}
	var fileStart time.Time
	hasMoreSet := false
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		meta := strings.TrimSpace(trimmed)
		if match := spartaArchiveTotal.FindStringSubmatch(meta); match != nil {
			if n, err := strconv.Atoi(match[1]); err == nil {
				page.Total = n
			}
			continue
		}
		if match := spartaArchiveHasMore.FindStringSubmatch(meta); match != nil {
			page.HasMore = match[1] != "0"
			hasMoreSet = true
			continue
		}
		if match := spartaArchiveStarted.FindStringSubmatch(meta); match != nil {
			stamp := strings.TrimSpace(match[1])
			if stamp != "" {
				if wall, err := time.ParseInLocation("2006-01-02 15:04:05", strings.Replace(stamp, "T", " ", 1), time.UTC); err == nil {
					page.EdgeStart = wall
				}
			}
			continue
		}
		if match := spartaArchiveFileLine.FindStringSubmatch(meta); match != nil {
			page.File = match[1]
			if ts := spartaArchiveFileTS.FindStringSubmatch(match[1]); ts != nil {
				if wall, err := time.ParseInLocation("20060102150405", ts[1]+ts[2], time.UTC); err == nil {
					fileStart = wall
				}
			}
			continue
		}
		msg := trimmed
		var at time.Time
		if match := spartaArchiveStamp.FindStringSubmatch(strings.TrimSpace(msg)); match != nil {
			if wall, err := time.ParseInLocation("2006-01-02 15:04:05", strings.Replace(match[1], "T", " ", 1), time.UTC); err == nil {
				at = wall
			}
		}
		page.Lines = append(page.Lines, JournalLine{Time: at, Message: msg})
	}
	if page.EdgeStart.IsZero() {
		page.EdgeStart = fileStart
	}
	// strings.Split leaves a trailing empty element when the remote output ends
	// with a newline; that must not advance the next page offset.
	if n := len(page.Lines); n > 0 && page.Lines[n-1].Message == "" {
		page.Lines = page.Lines[:n-1]
	}
	if !hasMoreSet {
		if page.Total > 0 {
			page.HasMore = offset+len(page.Lines) < page.Total
		} else {
			page.HasMore = len(page.Lines) >= limit
		}
	}
	return page
}

// SpartaAttackArchiveInfo locates an attack archive without reading its body.
type SpartaAttackArchiveInfo struct {
	Path string
	Name string
	Size int64
}

// ResolveSpartaAttackArchive finds the archive path and byte size on the edge.
// Missing files return a zero-value info and a nil error.
func ResolveSpartaAttackArchive(ctx context.Context, target SSHTarget, reqID string) (SpartaAttackArchiveInfo, error) {
	id, err := NormalizeSpartaReqID(reqID)
	if err != nil {
		return SpartaAttackArchiveInfo{}, err
	}
	client, err := dialSSH(ctx, target)
	if err != nil {
		return SpartaAttackArchiveInfo{}, err
	}
	defer client.Close()

	script := fmt.Sprintf(
		`timeout 10 sh -c '%s; `+
			`[ -n "$f" ] && [ -f "$f" ] || exit 0; `+
			`printf "%%s\\t%%s\\n" "$f" "$(wc -c < "$f")"'`,
		spartaFindAttackArchiveShell(id),
	)
	out, err := runRemoteScript(client, script)
	body := strings.TrimSpace(string(out))
	if err != nil && body == "" {
		return SpartaAttackArchiveInfo{}, err
	}
	if body == "" {
		return SpartaAttackArchiveInfo{}, nil
	}
	parts := strings.SplitN(body, "\t", 2)
	info := SpartaAttackArchiveInfo{Path: strings.TrimSpace(parts[0])}
	info.Name = path.Base(info.Path)
	if len(parts) > 1 {
		if n, parseErr := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64); parseErr == nil {
			info.Size = n
		}
	}
	return info, nil
}

// StreamSpartaAttackArchive copies the archive file from the edge to w.
// path must be a previously resolved archive under the Sparta attacks log dir.
func StreamSpartaAttackArchive(ctx context.Context, target SSHTarget, filePath string, w io.Writer) error {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" || strings.Contains(filePath, "'") || strings.Contains(filePath, "\n") {
		return fmt.Errorf("invalid archive path")
	}
	if !spartaAllowedAttackArchivePath(filePath) {
		return fmt.Errorf("archive path outside sparta attacks dir")
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
	// Reject path tricks; filePath already constrained to the attacks dir.
	script := fmt.Sprintf(`timeout 600 cat -- %q`, filePath)
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

// spartaFindAttackArchiveShell sets $f to the first matching attack archive under
// the current or legacy attacks directory. id must already be sanitized.
func spartaFindAttackArchiveShell(id string) string {
	return fmt.Sprintf(
		`f=; for d in %s %s; do `+
			`f=$(ls -1 "$d"/*-req_%s.log 2>/dev/null | head -n 1); `+
			`[ -n "$f" ] || f=$(ls -1 "$d"/*-%s.log 2>/dev/null | head -n 1); `+
			`[ -n "$f" ] && break; done`,
		spartaAttackLogDir, spartaAttackLogDirLegacy, id, id,
	)
}

func spartaAllowedAttackArchivePath(filePath string) bool {
	return strings.HasPrefix(filePath, spartaAttackLogDir+"/") ||
		strings.HasPrefix(filePath, spartaAttackLogDirLegacy+"/")
}

// TailSpartaLatestLog returns the newest lines from Sparta's live log file
// (/usr/local/share/dorian/sparta/logs/latest.log).
func TailSpartaLatestLog(ctx context.Context, target SSHTarget, lines int) ([]string, error) {
	if lines <= 0 || lines > 200 {
		lines = 80
	}
	client, err := dialSSH(ctx, target)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	script := fmt.Sprintf(
		`timeout 4 sh -c 'f=%q; [ -f "$f" ] || exit 0; tail -n %d -- "$f"'`,
		spartaLatestLogPath, lines,
	)
	out, err := runRemoteScript(client, script)
	body := strings.TrimSpace(string(out))
	if err != nil && body == "" {
		return nil, err
	}
	raw := strings.Split(string(out), "\n")
	logs := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-- ") {
			continue
		}
		logs = append(logs, line)
	}
	return logs, nil
}
