package api

import (
	"fmt"
	"strings"

	"vue-project-backend/internal/applog"
)

// logDeployLicenseClientf logs outbound calls from the API to deploy_license (never log secrets).
func logDeployLicenseClientf(format string, args ...any) {
	msg := strings.TrimSpace(strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", " "))
	logDeployLicenseEvent("client_log", map[string]any{"msg": msg})
}

// logDeployLicenseEvent logs a structured deploy-client event with explicit fields.
func logDeployLicenseEvent(event string, fields map[string]any) {
	applog.Event("info", "deploy_license_client", event, fields)
}

// oneLineLogPreview collapses whitespace and truncates for safe single-line logs.
func oneLineLogPreview(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return "…"
	}
	return s[:max-3] + "…"
}

func tokenPrefix(token string) string {
	t := strings.TrimSpace(token)
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "…"
}
