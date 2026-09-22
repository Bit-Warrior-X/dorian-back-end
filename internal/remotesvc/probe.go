package remotesvc

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

const (
	defaultSSHPort        = "22"
	defaultProbeAttempts  = 6
	defaultProbeInterval  = 2 * time.Second
	defaultDialTimeout    = 15 * time.Second
	defaultSessionTimeout = 20 * time.Second
	maxStatusReasonLen    = 280
)

// SSHTarget identifies a remote Dorian host for systemd probes.
type SSHTarget struct {
	Host     string
	User     string
	Password string
	Port     string
}

// RuntimeStatuses holds normalized runtime states for dashboard display.
type RuntimeStatuses struct {
	Angelos       string
	L4            string
	L7            string
	AngelosReason string
	L4Reason      string
	L7Reason      string
}

type unitProbeResult struct {
	ActiveState string
	Runtime     string
	Reason      string
}

func (t SSHTarget) dialAddr() string {
	host := strings.TrimSpace(t.Host)
	port := strings.TrimSpace(t.Port)
	if port == "" {
		port = defaultSSHPort
	}
	return net.JoinHostPort(host, port)
}

func normalizeSystemdState(raw string) string {
	state := strings.TrimSpace(raw)
	if state == "" {
		return "unknown"
	}
	if idx := strings.LastIndex(state, "\n"); idx >= 0 {
		state = strings.TrimSpace(state[idx+1:])
	}
	return strings.ToLower(state)
}

// mapSystemdToRuntime maps systemd ActiveState tokens to dashboard runtime status.
// Only a stably active unit counts as running; activating/deactivating means the
// unit is transitioning (including crash-loop auto-restart) and is not healthy.
func mapSystemdToRuntime(state string) string {
	switch normalizeSystemdState(state) {
	case "active", "reloading":
		return "running"
	case "failed", "inactive", "dead", "activating", "deactivating":
		return "stopped"
	default:
		return "unknown"
	}
}

func sanitizeReason(raw string) string {
	cleaned := strings.Join(strings.Fields(strings.TrimSpace(raw)), " ")
	if cleaned == "" {
		return ""
	}
	if utf8.RuneCountInString(cleaned) <= maxStatusReasonLen {
		return cleaned
	}
	runes := []rune(cleaned)
	return string(runes[:maxStatusReasonLen-1]) + "…"
}

func reasonFromUnitDetails(activeState, subState, result, execMainStatus, nRestarts, journal string) string {
	active := normalizeSystemdState(activeState)
	sub := strings.TrimSpace(subState)
	res := strings.TrimSpace(result)
	exit := strings.TrimSpace(execMainStatus)
	restarts := strings.TrimSpace(nRestarts)
	logLine := sanitizeReason(journal)

	switch active {
	case "active", "reloading":
		return ""
	case "failed":
		parts := []string{"Unit failed"}
		if res != "" && !strings.EqualFold(res, "success") {
			parts = append(parts, "result="+res)
		}
		if exit != "" && exit != "0" {
			parts = append(parts, "exit="+exit)
		}
		if restarts != "" && restarts != "0" {
			parts = append(parts, "restarts="+restarts)
		}
		if logLine != "" {
			parts = append(parts, logLine)
		}
		return sanitizeReason(strings.Join(parts, " · "))
	case "inactive", "dead":
		if strings.EqualFold(res, "exit-code") || (exit != "" && exit != "0") {
			parts := []string{"Stopped after process exit"}
			if exit != "" && exit != "0" {
				parts = append(parts, "exit="+exit)
			}
			if logLine != "" {
				parts = append(parts, logLine)
			}
			return sanitizeReason(strings.Join(parts, " · "))
		}
		if logLine != "" {
			return sanitizeReason("Service is inactive · " + logLine)
		}
		if sub != "" && sub != active {
			return sanitizeReason(fmt.Sprintf("Service is inactive (%s)", sub))
		}
		return "Service is inactive (stopped or not started)"
	case "activating":
		msg := "Service is starting"
		if restarts != "" && restarts != "0" {
			msg = fmt.Sprintf("Service is starting (restarts=%s)", restarts)
		}
		if logLine != "" {
			return sanitizeReason(msg + " · " + logLine)
		}
		return msg
	case "deactivating":
		return "Service is stopping"
	default:
		if active == "" || active == "unknown" {
			if logLine != "" {
				return sanitizeReason("Status unknown · " + logLine)
			}
			return "Status unknown — unit may be missing or unreachable"
		}
		msg := fmt.Sprintf("systemd state: %s", active)
		if logLine != "" {
			return sanitizeReason(msg + " · " + logLine)
		}
		return msg
	}
}

func probeUnit(client *ssh.Client, unit string) unitProbeResult {
	session, err := client.NewSession()
	if err != nil {
		return unitProbeResult{
			ActiveState: "unknown",
			Runtime:     "unknown",
			Reason:      "Unable to open SSH session for status probe",
		}
	}
	defer session.Close()

	_ = session.Setenv("LANG", "C")
	// First line: ActiveState (or failed/active shortcut).
	// Remaining fields: SubState|Result|ExecMainStatus|NRestarts|journal
	script := fmt.Sprintf(
		`unit=%q
active=$(systemctl is-active -- "$unit" 2>/dev/null || true)
if [ "$active" = "active" ] || [ "$active" = "reloading" ]; then
  printf '%%s\n||||\n' "$active"
  exit 0
fi
if systemctl is-failed -- "$unit" >/dev/null 2>&1; then
  active=failed
elif [ -z "$active" ]; then
  active=unknown
fi
show=$(systemctl show --property=ActiveState,SubState,Result,ExecMainStatus,NRestarts --value -- "$unit" 2>/dev/null || true)
active_state=$(printf '%%s\n' "$show" | sed -n '1p')
sub_state=$(printf '%%s\n' "$show" | sed -n '2p')
result=$(printf '%%s\n' "$show" | sed -n '3p')
exec_main=$(printf '%%s\n' "$show" | sed -n '4p')
n_restarts=$(printf '%%s\n' "$show" | sed -n '5p')
if [ -n "$active_state" ]; then
  active="$active_state"
fi
journal=$(journalctl -u "$unit" -n 3 --no-pager -o cat 2>/dev/null | sed '/^$/d' | tail -n 1 | tr '\n' ' ')
printf '%%s\n%%s|%%s|%%s|%%s|%%s\n' "$active" "$sub_state" "$result" "$exec_main" "$n_restarts" "$journal"`,
		unit,
	)
	out, err := session.CombinedOutput(script)
	if err != nil && len(out) == 0 {
		return unitProbeResult{
			ActiveState: "unknown",
			Runtime:     "unknown",
			Reason:      "Status probe failed on remote host",
		}
	}

	raw := strings.ReplaceAll(string(out), "\r\n", "\n")
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	active := "unknown"
	if len(lines) > 0 {
		active = normalizeSystemdState(lines[0])
	}
	subState, result, execMain, nRestarts, journal := "", "", "", "", ""
	if len(lines) > 1 {
		parts := strings.SplitN(lines[1], "|", 5)
		if len(parts) > 0 {
			subState = strings.TrimSpace(parts[0])
		}
		if len(parts) > 1 {
			result = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			execMain = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			nRestarts = strings.TrimSpace(parts[3])
		}
		if len(parts) > 4 {
			journal = strings.TrimSpace(parts[4])
		}
	}

	runtime := mapSystemdToRuntime(active)
	reason := ""
	if runtime != "running" {
		reason = reasonFromUnitDetails(active, subState, result, execMain, nRestarts, journal)
	}
	return unitProbeResult{
		ActiveState: active,
		Runtime:     runtime,
		Reason:      reason,
	}
}

func probeOnce(ctx context.Context, target SSHTarget) (RuntimeStatuses, error) {
	user := strings.TrimSpace(target.User)
	if user == "" {
		return RuntimeStatuses{}, fmt.Errorf("ssh user is required")
	}
	if strings.TrimSpace(target.Host) == "" {
		return RuntimeStatuses{}, fmt.Errorf("ssh host is required")
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(target.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         defaultDialTimeout,
	}

	dialer := &net.Dialer{Timeout: defaultDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", target.dialAddr())
	if err != nil {
		return RuntimeStatuses{}, fmt.Errorf("ssh dial %s: %w", target.dialAddr(), err)
	}
	defer conn.Close()

	cc, chans, reqs, err := ssh.NewClientConn(conn, target.dialAddr(), config)
	if err != nil {
		return RuntimeStatuses{}, fmt.Errorf("ssh handshake %s: %w", target.dialAddr(), err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()

	angelos := probeUnit(client, "angelos.service")
	sparta := probeUnit(client, "sparta.service")
	athens := probeUnit(client, "athens.service")

	return RuntimeStatuses{
		Angelos:       angelos.Runtime,
		L4:            sparta.Runtime,
		L7:            athens.Runtime,
		AngelosReason: angelos.Reason,
		L4Reason:      sparta.Reason,
		L7Reason:      athens.Reason,
	}, nil
}

func probeFailureStatuses(err error) RuntimeStatuses {
	msg := sanitizeReason(err.Error())
	if msg == "" {
		msg = "Unable to probe remote services over SSH"
	} else {
		msg = "Probe failed: " + msg
	}
	return RuntimeStatuses{
		Angelos:       "unknown",
		L4:            "unknown",
		L7:            "unknown",
		AngelosReason: msg,
		L4Reason:      msg,
		L7Reason:      msg,
	}
}

// ProbeDorianServices SSHes to the target and reads systemd state for
// angelos.service, sparta.service, and athens.service. Retries only on SSH errors.
func ProbeDorianServices(ctx context.Context, target SSHTarget) (RuntimeStatuses, error) {
	var last RuntimeStatuses
	var lastErr error

	for attempt := 1; attempt <= defaultProbeAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return last, err
		}
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return last, ctx.Err()
			case <-time.After(defaultProbeInterval):
			}
		}

		attemptCtx, cancel := context.WithTimeout(ctx, defaultSessionTimeout)
		statuses, err := probeOnce(attemptCtx, target)
		cancel()

		last = statuses
		lastErr = err
		if err == nil {
			return statuses, nil
		}
	}

	if lastErr != nil {
		return probeFailureStatuses(lastErr), lastErr
	}
	return last, nil
}
