package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"vue-project-backend/internal/store"
)

const (
	auditMaxChangeLines = 20
	auditMaxValueLength = 120
	auditMaxListNames   = 20
)

// auditResolver looks up human-readable names for audit targets.
type auditResolver struct {
	users    store.UserStore
	servers  store.ServerStore
	sites    store.SiteStore
	wafRules store.WafRuleStore
}

type auditTarget struct {
	Label string
	State map[string]any
}

func (res *auditResolver) loadTarget(ctx context.Context, resourceType string, id int64) (auditTarget, bool) {
	if res == nil || id <= 0 {
		return auditTarget{}, false
	}
	switch resourceType {
	case "user":
		if res.users == nil {
			return auditTarget{}, false
		}
		user, err := res.users.FindByID(ctx, id)
		if err != nil {
			return auditTarget{}, false
		}
		return auditTarget{Label: auditUserLabel(user.Name, user.Email), State: auditStateOf(user)}, true
	case "edge":
		if res.servers == nil {
			return auditTarget{}, false
		}
		view, err := res.servers.GetView(ctx, id)
		if err != nil {
			return auditTarget{}, false
		}
		return auditTarget{Label: auditEdgeLabel(view.Name, view.IP), State: auditStateOf(view)}, true
	case "site":
		if res.sites == nil {
			return auditTarget{}, false
		}
		site, err := res.sites.Get(ctx, id)
		if err != nil {
			return auditTarget{}, false
		}
		return auditTarget{Label: site.Domain, State: auditStateOf(site)}, true
	case "waf_rule":
		if res.wafRules == nil {
			return auditTarget{}, false
		}
		rule, err := res.wafRules.Get(ctx, id)
		if err != nil {
			return auditTarget{}, false
		}
		return auditTarget{Label: rule.Name, State: auditStateOf(rule)}, true
	}
	return auditTarget{}, false
}

// labelFromValues builds a target label for a new resource from the request body or
// the JSON response of the create call.
func auditLabelFromValues(resourceType string, values map[string]any) string {
	get := func(key string) string { return auditBodyString(values, key) }
	switch resourceType {
	case "user":
		return auditUserLabel(get("name"), get("email"))
	case "edge":
		return auditEdgeLabel(get("name"), get("ip"))
	case "site":
		return get("domain")
	default:
		return get("name")
	}
}

func auditUserLabel(name, email string) string {
	name, email = strings.TrimSpace(name), strings.TrimSpace(email)
	switch {
	case name != "" && email != "":
		return name + " <" + email + ">"
	case name != "":
		return name
	default:
		return email
	}
}

func auditEdgeLabel(name, ip string) string {
	name, ip = strings.TrimSpace(name), strings.TrimSpace(ip)
	switch {
	case name != "" && ip != "":
		return name + " (" + ip + ")"
	case name != "":
		return name
	default:
		return ip
	}
}

func auditStateOf(value any) map[string]any {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var state map[string]any
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil
	}
	return state
}

// diffLines describes what changed between two snapshots of the same resource.
// Only fields sent in the request body (plus extra) are compared, so unrelated
// background updates (e.g. runtime status) do not show up.
func (res *auditResolver) diffLines(ctx context.Context, before, after, body map[string]any, extra []string) []string {
	keys := make([]string, 0, len(body)+len(extra))
	seen := map[string]bool{}
	add := func(key string) {
		if seen[key] || auditSkipField(key) {
			return
		}
		seen[key] = true
		keys = append(keys, key)
	}
	for key := range body {
		add(key)
	}
	for _, key := range extra {
		add(key)
	}
	sortAuditKeys(keys)

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		oldValue, inBefore := before[key]
		newValue, inAfter := after[key]
		if !inBefore && !inAfter {
			if key == "resetSshHostKey" {
				if reset, _ := body[key].(bool); reset {
					lines = append(lines, "Trusted SSH host key: reset (next connection re-pins the edge's key)")
				}
				continue
			}
			// Write-only fields such as a user's password never appear in snapshots.
			if auditSensitiveField(key) && auditHasValue(body[key]) {
				lines = append(lines, auditFieldLabel(key)+": changed")
			}
			continue
		}
		if auditValuesEqual(oldValue, newValue) {
			continue
		}
		if auditSensitiveField(key) {
			lines = append(lines, auditFieldLabel(key)+": changed")
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: %s → %s",
			auditFieldLabel(key), res.formatValue(ctx, key, oldValue), res.formatValue(ctx, key, newValue)))
	}
	return capAuditLines(lines)
}

// valueLines lists the submitted values of a request body.
func (res *auditResolver) valueLines(ctx context.Context, body any) []string {
	switch typed := body.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key, value := range typed {
			if auditSkipField(key) || !auditHasValue(value) {
				continue
			}
			keys = append(keys, key)
		}
		sortAuditKeys(keys)
		lines := make([]string, 0, len(keys))
		for _, key := range keys {
			if auditSensitiveField(key) {
				lines = append(lines, auditFieldLabel(key)+": provided")
				continue
			}
			lines = append(lines, auditFieldLabel(key)+": "+res.formatValue(ctx, key, typed[key]))
		}
		return capAuditLines(lines)
	case []any:
		if len(typed) == 0 {
			return nil
		}
		return []string{"Items: " + res.formatValue(ctx, "items", typed)}
	}
	return nil
}

func (res *auditResolver) formatValue(ctx context.Context, key string, value any) string {
	switch typed := value.(type) {
	case nil:
		return "none"
	case string:
		if strings.TrimSpace(typed) == "" {
			return "empty"
		}
		return truncateAuditValue(typed)
	case bool:
		if typed {
			return "yes"
		}
		return "no"
	case float64:
		if key == "wafId" {
			return res.wafRuleName(ctx, int64(typed))
		}
		return formatAuditNumber(typed)
	case []any:
		if len(typed) == 0 {
			return "none"
		}
		if names := res.idListNames(ctx, key, typed); names != "" {
			return names
		}
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, res.formatValue(ctx, "", item))
		}
		return truncateAuditValue(strings.Join(parts, ", "))
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return "…"
		}
		return truncateAuditValue(string(raw))
	}
}

// idListNames renders lists of edge/user IDs as names.
func (res *auditResolver) idListNames(ctx context.Context, key string, ids []any) string {
	if res == nil {
		return ""
	}
	var lookup func(int64) string
	switch key {
	case "serverIds":
		if res.servers == nil {
			return ""
		}
		lookup = func(id int64) string {
			if view, err := res.servers.GetView(ctx, id); err == nil {
				return auditEdgeLabel(view.Name, view.IP)
			}
			return fmt.Sprintf("edge #%d", id)
		}
	case "userIds", "managedUserIds":
		if res.users == nil {
			return ""
		}
		lookup = func(id int64) string {
			if user, err := res.users.FindByID(ctx, id); err == nil {
				return auditUserLabel(user.Name, user.Email)
			}
			return fmt.Sprintf("user #%d", id)
		}
	default:
		return ""
	}
	names := make([]string, 0, len(ids))
	for i, raw := range ids {
		if i == auditMaxListNames {
			names = append(names, fmt.Sprintf("+%d more", len(ids)-i))
			break
		}
		number, ok := raw.(float64)
		if !ok {
			return ""
		}
		names = append(names, lookup(int64(number)))
	}
	return strings.Join(names, ", ")
}

func (res *auditResolver) wafRuleName(ctx context.Context, id int64) string {
	if id <= 0 {
		return "none"
	}
	if res != nil && res.wafRules != nil {
		if rule, err := res.wafRules.Get(ctx, id); err == nil && rule.Name != "" {
			return rule.Name
		}
	}
	return fmt.Sprintf("rule set #%d", id)
}

var auditFieldLabels = map[string]string{
	"name": "Name", "email": "Email", "role": "Role", "status": "Status",
	"password": "Password", "ip": "IP", "domain": "Domain",
	"sshUser": "SSH user", "sshPort": "SSH port", "sshPassword": "SSH password",
	"sshPrivateKey": "SSH private key", "sshKeyPassphrase": "SSH key passphrase",
	"sshAuthType": "SSH authentication",
	"serverIds":   "Edges", "userIds": "Management users", "managedUserIds": "Management users",
	"licenseType": "License", "license": "License", "billingPeriod": "Billing period",
	"licenseFile": "License file", "expiredDate": "Expires", "version": "Version",
	"versionUuid": "Version", "wafId": "WAF rule set", "sslType": "SSL type",
	"sslCert": "SSL certificate", "sslCertKey": "SSL private key", "service": "Service",
	"action": "Action", "url": "URL", "urls": "URLs", "ip_address": "IP address",
	"expiresAt": "Expires", "scopes": "Scopes",
}

var auditFieldOrder = []string{"name", "domain", "email", "ip", "role", "status", "licenseType", "license"}

func auditFieldLabel(key string) string {
	if label, ok := auditFieldLabels[key]; ok {
		return label
	}
	var b strings.Builder
	for i, r := range key {
		switch {
		case r == '_' || r == '-':
			b.WriteRune(' ')
		case r >= 'A' && r <= 'Z' && i > 0:
			b.WriteRune(' ')
			b.WriteRune(r + ('a' - 'A'))
		case i == 0 && r >= 'a' && r <= 'z':
			b.WriteRune(r - ('a' - 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sortAuditKeys(keys []string) {
	rank := func(key string) int {
		for i, candidate := range auditFieldOrder {
			if candidate == key {
				return i
			}
		}
		return len(auditFieldOrder)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		ri, rj := rank(keys[i]), rank(keys[j])
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
}

func auditSkipField(key string) bool {
	switch key {
	case "id", "currentPassword", "code", "createdAt", "updatedAt", "created", "hasPassword":
		return true
	}
	return false
}

func auditSensitiveField(key string) bool {
	lower := strings.ToLower(key)
	if lower == "pass" {
		return true
	}
	for _, marker := range []string{"password", "passphrase", "secret", "token", "privatekey", "private_key", "ssh_key", "certkey", "sslcert", "licensefile"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func auditHasValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	}
	return true
}

func auditValuesEqual(a, b any) bool {
	rawA, errA := json.Marshal(a)
	rawB, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(rawA) == string(rawB)
}

func formatAuditNumber(value float64) string {
	if value == math.Trunc(value) && math.Abs(value) < 1e15 {
		return fmt.Sprintf("%d", int64(value))
	}
	return fmt.Sprintf("%g", value)
}

func truncateAuditValue(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len([]rune(value)) <= auditMaxValueLength {
		return value
	}
	return string([]rune(value)[:auditMaxValueLength]) + "…"
}

func capAuditLines(lines []string) []string {
	if len(lines) <= auditMaxChangeLines {
		return lines
	}
	extra := len(lines) - auditMaxChangeLines
	return append(lines[:auditMaxChangeLines], fmt.Sprintf("… and %d more", extra))
}
