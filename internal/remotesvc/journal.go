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
// Lines are formatted as "[YYYY-MM-DD HH:MM:SS] message" using the journal clock.
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

	script := fmt.Sprintf(`timeout 4 journalctl -u %q -n %d --no-pager -o short-unix`, unit, lines)
	out, err := runRemoteScript(client, script)
	if err != nil && len(strings.TrimSpace(string(out))) == 0 {
		return nil, err
	}
	entries := parseShortUnixJournal(string(out))
	logs := make([]string, 0, len(entries))
	for _, entry := range entries {
		msg := strings.TrimSpace(entry.Message)
		if msg == "" {
			continue
		}
		logs = append(logs, fmt.Sprintf("[%s] %s", entry.Time.UTC().Format("2006-01-02 15:04:05"), msg))
	}
	return logs, nil
}

// TailEdgeServiceLog returns the newest live lines for Angelos, Sparta, or Athens.
// Sparta prefers latest.log then journal; Athens prefers athens_error.log then
// journal; Angelos uses the systemd journal.
func TailEdgeServiceLog(ctx context.Context, target SSHTarget, service string, lines int) ([]string, error) {
	name := strings.ToLower(strings.TrimSpace(service))
	if lines <= 0 || lines > 200 {
		lines = 80
	}
	switch name {
	case "sparta":
		fileLines, err := TailSpartaLatestLog(ctx, target, lines)
		if err == nil && len(fileLines) > 0 {
			return fileLines, nil
		}
		journal, journalErr := TailServiceJournal(ctx, target, "sparta", lines)
		if journalErr == nil && len(journal) > 0 {
			return journal, nil
		}
		if err != nil {
			return nil, err
		}
		return journal, journalErr
	case "athens":
		fileLines, err := TailAthensErrorLog(ctx, target, lines)
		if err == nil && len(fileLines) > 0 {
			return fileLines, nil
		}
		journal, journalErr := TailServiceJournal(ctx, target, "athens", lines)
		if journalErr == nil && len(journal) > 0 {
			return journal, nil
		}
		if err != nil {
			return nil, err
		}
		return journal, journalErr
	case "angelos":
		return TailServiceJournal(ctx, target, name, lines)
	default:
		return nil, fmt.Errorf("unsupported service %q", service)
	}
}
