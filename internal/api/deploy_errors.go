package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

// deployLicenseErrorBody matches error JSON from dorian-license-server.
type deployLicenseErrorBody struct {
	Code        int    `json:"code"`
	Description string `json:"description"`
	Message     string `json:"message"`
	Error       string `json:"error"`
	ScriptError string `json:"script_error"`
	Stderr      string `json:"stderr"`
	Stdout      string `json:"stdout"`
	Path        string `json:"path"`
}

func firstNonEmptyTrimmed(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func extractDeployLicenseErrorDetail(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	var body deployLicenseErrorBody
	if err := json.Unmarshal([]byte(raw), &body); err == nil {
		detail := firstNonEmptyTrimmed(
			body.Message,
			body.ScriptError,
			body.Error,
			body.Description,
			body.Stderr,
		)
		if detail != "" {
			// Prefer script_error when description is a generic wrapper.
			generic := strings.EqualFold(strings.TrimSpace(body.Description), "generate_license.sh failed") ||
				strings.EqualFold(strings.TrimSpace(body.Description), "create_server failed") ||
				strings.EqualFold(strings.TrimSpace(body.Description), "upgrade_license failed") ||
				strings.EqualFold(strings.TrimSpace(body.Description), "upgrade_version failed")
			if generic {
				detail = firstNonEmptyTrimmed(body.Message, body.ScriptError, body.Error, body.Description)
			}
			return detail
		}
	}

	// Nested JSON after a status prefix, e.g. "… status 500: {...}"
	if idx := strings.Index(raw, "{"); idx >= 0 {
		if nested := extractDeployLicenseErrorDetail(raw[idx:]); nested != "" {
			return nested
		}
	}
	return raw
}

func humanizeDeployLicenseError(detail string) string {
	d := strings.TrimSpace(detail)
	if d == "" {
		return ""
	}
	lower := strings.ToLower(d)

	switch {
	case strings.Contains(lower, "license not found"):
		return "The selected license file was not found. Load a valid license or generate a new one, or try a different server."
	case strings.Contains(lower, "no license row"):
		return "No license record exists for this deployment. Generate a new license or try a different server."
	case strings.Contains(lower, "failed to get remote machine id"),
		strings.Contains(lower, "could not obtain machine id"),
		strings.Contains(lower, "empty machine id"),
		strings.Contains(lower, "ssh test failed"):
		return d + " Check SSH IP, port, and credentials, then try another host if this one cannot be licensed."
	case strings.Contains(lower, "permission denied"),
		strings.Contains(lower, "authentication failed"),
		strings.Contains(lower, "unable to authenticate"):
		return d + " Verify the SSH username and password, or try a different server."
	case strings.Contains(lower, "connection refused"),
		strings.Contains(lower, "no route to host"),
		strings.Contains(lower, "network is unreachable"),
		strings.Contains(lower, "timed out"),
		strings.Contains(lower, "i/o timeout"):
		return d + " The host may be unreachable from the control plane — try another server."
	case strings.Contains(lower, "no dorian product path"),
		strings.Contains(lower, "version not found"),
		strings.Contains(lower, "no_version"):
		return d + " No matching product package is available for this host OS."
	default:
		return d
	}
}

func formatDeployLicenseHTTPError(op string, status int, body []byte) error {
	raw := strings.TrimSpace(string(body))
	detail := humanizeDeployLicenseError(extractDeployLicenseErrorDetail(raw))
	if detail == "" {
		return fmt.Errorf(
			"%s failed (HTTP %d). Check SSH reachability and license availability, then try another server if needed",
			op,
			status,
		)
	}
	// Keep message customer-facing; full raw body is already logged by the caller.
	if status > 0 {
		return fmt.Errorf("%s failed (HTTP %d): %s", op, status, detail)
	}
	return fmt.Errorf("%s failed: %s", op, detail)
}

func formatProbeHostOSError(sshUser, ip string, err error) string {
	detail := strings.TrimSpace(err.Error())
	lower := strings.ToLower(detail)
	host := strings.TrimSpace(ip)
	user := strings.TrimSpace(sshUser)
	target := host
	if user != "" && host != "" {
		target = user + "@" + host
	}

	switch {
	case strings.Contains(lower, "i/o timeout"),
		strings.Contains(lower, "timed out"),
		strings.Contains(lower, "deadline exceeded"):
		return fmt.Sprintf(
			"Cannot reach %s over SSH (connection timed out). The control plane cannot open port 22 to this host — check firewall/security group, or try a different server.",
			target,
		)
	case strings.Contains(lower, "connection refused"):
		return fmt.Sprintf(
			"Cannot reach %s over SSH (connection refused). Confirm sshd is listening and the port is correct, or try a different server.",
			target,
		)
	case strings.Contains(lower, "no route to host"),
		strings.Contains(lower, "network is unreachable"):
		return fmt.Sprintf(
			"Cannot reach %s over SSH (network unreachable). Try a different server reachable from the control plane.",
			target,
		)
	case strings.Contains(lower, "unable to authenticate"),
		strings.Contains(lower, "handshake"),
		strings.Contains(lower, "permission denied"):
		return fmt.Sprintf(
			"SSH authentication failed for %s: %s. Verify username/password, or try a different server.",
			target,
			detail,
		)
	default:
		return fmt.Sprintf(
			"Failed to detect host OS on %s: %s. Check SSH reachability and credentials, or try a different server.",
			target,
			detail,
		)
	}
}
