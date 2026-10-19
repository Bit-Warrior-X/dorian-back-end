package remotesvc

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// JournalLine is one journal entry. Time comes from the journal's own UTC epoch,
// so it is independent of the edge's local timezone.
type JournalLine struct {
	Time    time.Time
	Message string
}

// ServiceJournalRange returns up to maxLines of the newest journal entries for a
// Dorian unit between since and until. A non-empty match is an extended regex
// applied on the edge before the line limit; it must not contain a single quote.
func ServiceJournalRange(ctx context.Context, target SSHTarget, service string, since, until time.Time, match string, maxLines int) ([]JournalLine, error) {
	unit, err := serviceUnitName(service)
	if err != nil {
		return nil, err
	}
	if strings.Contains(match, "'") {
		return nil, fmt.Errorf("invalid journal match")
	}
	if maxLines <= 0 || maxLines > 5000 {
		maxLines = 2000
	}
	client, err := dialSSH(ctx, target)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	script := fmt.Sprintf(`timeout 6 journalctl -u %q --since @%d --until @%d --no-pager -o short-unix`,
		unit, since.Unix(), until.Unix())
	if match != "" {
		script += fmt.Sprintf(` | grep -E '%s'`, match)
	}
	script += fmt.Sprintf(` | tail -n %d`, maxLines)
	out, err := runRemoteScript(client, script)
	if err != nil && len(strings.TrimSpace(string(out))) == 0 {
		return nil, err
	}
	return parseShortUnixJournal(string(out)), nil
}

func parseShortUnixJournal(raw string) []JournalLine {
	lines := strings.Split(raw, "\n")
	out := make([]JournalLine, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-- ") {
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			continue
		}
		epoch, err := strconv.ParseFloat(parts[0], 64)
		if err != nil {
			continue
		}
		message := parts[2]
		if idx := strings.Index(message, ": "); idx >= 0 {
			message = message[idx+2:]
		}
		sec := int64(epoch)
		out = append(out, JournalLine{
			Time:    time.Unix(sec, int64((epoch-float64(sec))*1e9)).UTC(),
			Message: strings.TrimSpace(message),
		})
	}
	return out
}

// TailServiceJournal returns the newest journal lines for a Dorian unit.
func TailServiceJournal(ctx context.Context, target SSHTarget, service string, lines int) ([]string, error) {
	unit, err := serviceUnitName(service)
	if err != nil {
		return nil, err
	}
	if lines <= 0 || lines > 80 {
		lines = 40
	}
	client, err := dialSSH(ctx, target)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	script := fmt.Sprintf(`timeout 4 journalctl -u %q -n %d --no-pager -o cat`, unit, lines)
	out, err := runRemoteScript(client, script)
	if err != nil && len(strings.TrimSpace(string(out))) == 0 {
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
