package api

import (
	"net/http"
	"strconv"
	"strings"
)

// auditClassification describes how a mutating request is recorded.
//
// Summary is written with a base-form verb ("Delete user {target}"); it is turned
// into "Deleted user …" on success and "Failed to delete user …" on failure.
// {target} is replaced by the resolved resource label.
type auditClassification struct {
	ShouldLog    bool
	Action       string
	Category     string
	ResourceType string
	ResourceID   int64
	ResourceName string
	Summary      string
	// Describe builds Summary from the request body when the wording depends on it.
	Describe func(body map[string]any) string
	// Details is used verbatim (login/logout entries written by handlers).
	Details string
	// Diff compares the target before/after the request for the fields sent in the body.
	Diff bool
	// DiffFields are compared before/after regardless of the body.
	DiffFields []string
	// BodyValues lists the submitted values (secrets masked).
	BodyValues bool
	// SelfTarget means the target is the acting user (2FA changes).
	SelfTarget bool
}

var auditWafSectionLabels = map[string]string{
	"whitelist":           "IP allowlist",
	"blacklist":           "IP blocklist",
	"geolocation":         "geo blocking",
	"anti-cc":             "anti-CC",
	"anti-header":         "header rules",
	"interval-freq-limit": "interval rate limit",
	"second-freq-limit":   "per-second rate limit",
	"response-freq":       "response rate limit",
	"user-agent":          "User-Agent rules",
}

var auditServiceLabels = map[string]string{
	"angelos": "Angelos agent",
	"sparta":  "Sparta (L4)",
	"athens":  "Athens (L7)",
}

func normalizeAuditPath(path string) string {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, "/api/v1/") {
		path = strings.TrimPrefix(path, "/api/v1")
	}
	return strings.TrimSuffix(path, "/")
}

func classifyAuditRequest(method, path string) auditClassification {
	method = strings.ToUpper(strings.TrimSpace(method))
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return auditClassification{}
	}

	segs := strings.Split(strings.TrimPrefix(normalizeAuditPath(path), "/"), "/")
	switch segs[0] {
	case "users":
		return classifyUserAudit(method, segs)
	case "auth":
		return classifyAuthAudit(method, segs)
	case "servers":
		if len(segs) > 1 && segs[1] == "blacklist" {
			return classifyBlacklistAudit(method, segs)
		}
		return classifyEdgeAudit(method, segs)
	case "sites":
		return classifySiteAudit(method, segs)
	case "waf-rules":
		return classifyWafRuleAudit(method, segs)
	}
	return auditClassification{}
}

func classifyUserAudit(method string, segs []string) auditClassification {
	base := auditClassification{ShouldLog: true, Category: "user", ResourceType: "user"}
	if len(segs) == 1 {
		if method != http.MethodPost {
			return auditClassification{}
		}
		base.Action, base.Summary, base.BodyValues = "create", "Create user {target}", true
		return base
	}
	if segs[1] == "batch-delete" {
		base.Action, base.Summary, base.BodyValues = "batch_delete", "Delete users (batch)", true
		return base
	}
	base.ResourceID = parseAuditID(segs[1])
	if len(segs) == 3 && segs[2] == "mfa" && method == http.MethodDelete {
		base.Action, base.Category, base.Summary = "mfa_reset", "auth", "Reset two-factor authentication for user {target}"
		return base
	}
	if len(segs) > 2 {
		return auditClassification{}
	}
	switch method {
	case http.MethodPut, http.MethodPatch:
		base.Action, base.Summary, base.Diff = "update", "Update user {target}", true
	case http.MethodDelete:
		base.Action, base.Summary = "delete", "Delete user {target}"
	default:
		return auditClassification{}
	}
	return base
}

func classifyAuthAudit(method string, segs []string) auditClassification {
	if len(segs) < 2 {
		return auditClassification{}
	}
	switch segs[1] {
	case "mfa":
		if len(segs) != 3 || method != http.MethodPost {
			return auditClassification{}
		}
		class := auditClassification{ShouldLog: true, Category: "auth", ResourceType: "user", SelfTarget: true}
		switch segs[2] {
		case "enable":
			class.Action, class.Summary = "mfa_enable", "Enable two-factor authentication"
		case "disable":
			class.Action, class.Summary = "mfa_disable", "Disable two-factor authentication"
		case "recovery-codes":
			class.Action, class.Summary = "recovery_codes", "Regenerate two-factor recovery codes"
		default:
			return auditClassification{}
		}
		return class
	case "api-tokens":
		class := auditClassification{ShouldLog: true, Category: "api_token", ResourceType: "api_token"}
		if len(segs) == 2 && method == http.MethodPost {
			class.Action, class.Summary, class.BodyValues = "token_create", "Create API token {target}", true
			return class
		}
		if len(segs) == 3 && method == http.MethodDelete {
			class.ResourceID = parseAuditID(segs[2])
			class.Action, class.Summary = "token_revoke", "Revoke API token {target}"
			return class
		}
	}
	return auditClassification{}
}

func classifyBlacklistAudit(method string, segs []string) auditClassification {
	class := auditClassification{ShouldLog: true, Category: "blacklist", ResourceType: "blacklist", BodyValues: true}
	if len(segs) > 2 {
		class.ResourceID = parseAuditID(segs[2])
	}
	switch method {
	case http.MethodPost:
		class.Action, class.Summary = "create", "Add entry to blocked list"
	case http.MethodPut, http.MethodPatch:
		class.Action, class.Summary = "update", "Update blocked list entry {target}"
	case http.MethodDelete:
		if class.ResourceID > 0 {
			class.Action, class.Summary = "delete", "Remove blocked list entry {target}"
		} else {
			class.Action, class.Summary = "batch_delete", "Remove blocked list entries"
		}
	}
	return class
}

func classifyEdgeAudit(method string, segs []string) auditClassification {
	base := auditClassification{ShouldLog: true, Category: "edge", ResourceType: "edge"}
	if len(segs) == 1 {
		if method != http.MethodPost {
			return auditClassification{}
		}
		base.Action, base.Summary, base.BodyValues = "create", "Create edge {target}", true
		return base
	}
	if segs[1] == "batch-delete" {
		base.Action, base.Summary, base.BodyValues = "batch_delete", "Delete edges (batch)", true
		return base
	}
	base.ResourceID = parseAuditID(segs[1])
	if len(segs) == 2 {
		switch method {
		case http.MethodPut, http.MethodPatch:
			base.Action, base.Summary, base.Diff = "update", "Update edge {target}", true
		case http.MethodDelete:
			base.Action, base.Summary = "delete", "Delete edge {target}"
		default:
			return auditClassification{}
		}
		return base
	}

	switch segs[2] {
	case "refresh-runtime-status", "host-metrics", "access-log":
		return auditClassification{}
	case "users":
		base.Action, base.Summary = "assign", "Change management users of edge {target}"
		base.DiffFields = []string{"managedUserIds"}
	case "service-control":
		base.Action = "operate"
		base.Describe = func(body map[string]any) string {
			verb := "Start"
			if strings.EqualFold(auditBodyString(body, "action"), "stop") {
				verb = "Stop"
			}
			service := auditBodyString(body, "service")
			if label, ok := auditServiceLabels[strings.ToLower(service)]; ok {
				service = label
			}
			if service == "" {
				service = "a"
			}
			return verb + " " + service + " service on edge {target}"
		}
	case "host-power":
		base.Action = "operate"
		base.Describe = func(body map[string]any) string {
			if strings.EqualFold(auditBodyString(body, "action"), "poweroff") {
				return "Power off the host of edge {target}"
			}
			return "Reboot the host of edge {target}"
		}
	case "upgrade":
		base.Action, base.Summary = "upgrade", "Upgrade Angelos on edge {target}"
		base.DiffFields = []string{"version"}
	case "upgrade-license":
		base.Action, base.BodyValues = "upgrade", true
		base.DiffFields = []string{"license", "expiredDate"}
		base.Describe = func(body map[string]any) string {
			if tier := auditBodyString(body, "licenseType"); tier != "" {
				return "Change license of edge {target} to " + tier
			}
			return "Change license of edge {target}"
		}
	case "listening-ports":
		base.Category = "listening_port"
		applySubResourceAudit(&base, method, segs[3:], "listening port", "edge {target}")
	case "l4":
		base.Category = "l4"
		classifyEdgeL4Audit(&base, method, segs[3:])
	case "waf":
		base.Category = "waf"
		section := "WAF settings"
		if len(segs) > 3 {
			section = auditWafSectionLabel(segs[3])
		}
		applySubResourceAudit(&base, method, trimAuditSegments(segs, 4), section+" entry", "edge {target}")
	default:
		applySubResourceAudit(&base, method, trimAuditSegments(segs, 3), strings.Join(segs[2:], "/"), "edge {target}")
	}
	return base
}

func classifyEdgeL4Audit(class *auditClassification, method string, rest []string) {
	class.BodyValues = true
	if len(rest) == 0 {
		class.Action, class.Summary = "update", "Update L4 DDoS protection settings on edge {target}"
		return
	}
	switch rest[0] {
	case "options":
		class.Action, class.Summary = "update", "Update L4 options on edge {target}"
	case "whitelist", "blacklist":
		list := "L4 allowlist"
		if rest[0] == "blacklist" {
			list = "L4 blocklist"
		}
		switch {
		case len(rest) > 1 && rest[1] == "clear":
			class.Action, class.Summary = "delete", "Clear the "+list+" on edge {target}"
		case len(rest) > 2 && rest[1] == "remove":
			class.Action, class.Summary = "delete", "Remove "+rest[2]+" from the "+list+" on edge {target}"
		default:
			applySubResourceAudit(class, method, rest[1:], list+" entry", "edge {target}")
		}
	default:
		applySubResourceAudit(class, method, rest[1:], "L4 "+rest[0], "edge {target}")
	}
}

func classifySiteAudit(method string, segs []string) auditClassification {
	base := auditClassification{ShouldLog: true, Category: "site", ResourceType: "site"}
	if len(segs) == 1 {
		if method != http.MethodPost {
			return auditClassification{}
		}
		base.Action, base.Summary, base.BodyValues = "create", "Create site {target}", true
		return base
	}
	if segs[1] == "batch-delete" {
		base.Action, base.Summary, base.BodyValues = "batch_delete", "Delete sites (batch)", true
		return base
	}
	base.ResourceID = parseAuditID(segs[1])
	if len(segs) == 2 {
		switch method {
		case http.MethodPut, http.MethodPatch:
			base.Action, base.Summary, base.Diff = "update", "Update site {target}", true
		case http.MethodDelete:
			base.Action, base.Summary = "delete", "Delete site {target}"
		default:
			return auditClassification{}
		}
		return base
	}

	rest := segs[3:]
	switch segs[2] {
	case "upstream-servers":
		base.Category = "origin"
		applySubResourceAudit(&base, method, rest, "origin server", "site {target}")
	case "cache-rules":
		base.Category = "cache"
		switch {
		case len(rest) > 0 && rest[0] == "clear-cache":
			base.Action, base.Summary, base.BodyValues = "operate", "Purge all cached content for site {target}", true
		case len(rest) > 0 && rest[0] == "clear-url-cache":
			base.Action, base.Summary, base.BodyValues = "operate", "Purge cached URLs for site {target}", true
		default:
			applySubResourceAudit(&base, method, rest, "cache rule", "site {target}")
		}
	case "compress":
		base.Category = "compress"
		base.Action, base.Summary, base.BodyValues = "update", "Update compression settings for site {target}", true
	case "ports":
		base.Category = "ports"
		base.Action, base.Summary, base.BodyValues = "update", "Update edge ports for site {target}", true
	case "certificate":
		base.Category = "certificate"
		if len(rest) > 0 && rest[0] == "renew" {
			base.Action, base.Summary, base.BodyValues = "operate", "Request certificate renewal for site {target}", true
		} else {
			base.Action, base.Summary, base.BodyValues = "update", "Update SSL certificate for site {target}", true
		}
	case "waf":
		base.Category = "waf"
		switch {
		case len(rest) > 0 && rest[0] == "fork":
			base.Action, base.Summary, base.BodyValues = "fork", "Fork the WAF rule set of site {target}", true
		case len(rest) == 0:
			base.Action, base.Summary, base.BodyValues = "update", "Change the WAF rule set of site {target}", true
			base.DiffFields = []string{"wafId"}
		default:
			applySubResourceAudit(&base, method, rest[1:], auditWafSectionLabel(rest[0])+" entry", "site {target}")
		}
	default:
		applySubResourceAudit(&base, method, rest, strings.Join(segs[2:], "/"), "site {target}")
	}
	return base
}

func classifyWafRuleAudit(method string, segs []string) auditClassification {
	base := auditClassification{ShouldLog: true, Category: "waf_rule", ResourceType: "waf_rule"}
	if len(segs) == 1 {
		if method != http.MethodPost {
			return auditClassification{}
		}
		base.Action, base.Summary, base.BodyValues = "create", "Create WAF rule set {target}", true
		return base
	}
	if segs[1] == "batch-delete" {
		base.Action, base.Summary, base.BodyValues = "batch_delete", "Delete WAF rule sets (batch)", true
		return base
	}
	base.ResourceID = parseAuditID(segs[1])
	if len(segs) == 2 {
		switch method {
		case http.MethodPut, http.MethodPatch:
			base.Action, base.Summary, base.Diff = "update", "Update WAF rule set {target}", true
		case http.MethodDelete:
			base.Action, base.Summary = "delete", "Delete WAF rule set {target}"
		default:
			return auditClassification{}
		}
		return base
	}
	switch segs[2] {
	case "duplicate":
		base.Action, base.Summary, base.BodyValues = "duplicate", "Duplicate WAF rule set {target}", true
	case "waf":
		base.Category = "waf"
		section := "rule"
		if len(segs) > 3 {
			section = auditWafSectionLabel(segs[3])
		}
		applySubResourceAudit(&base, method, trimAuditSegments(segs, 4), section+" entry", "WAF rule set {target}")
	default:
		applySubResourceAudit(&base, method, trimAuditSegments(segs, 3), strings.Join(segs[2:], "/"), "WAF rule set {target}")
	}
	return base
}

// applySubResourceAudit fills in a create/update/delete of a child item (cache rule,
// origin server, WAF entry, …). rest holds the path segments after the collection name.
func applySubResourceAudit(class *auditClassification, method string, rest []string, item, parent string) {
	class.BodyValues = true
	itemRef := item
	if len(rest) > 0 && rest[0] != "" && rest[0] != "batch-delete" {
		itemRef = item + " #" + rest[0]
	}
	if len(rest) > 0 && rest[0] == "batch-delete" {
		class.Action, class.Summary = "batch_delete", "Remove "+item+"s (batch) from "+parent
		return
	}
	switch method {
	case http.MethodPost:
		class.Action, class.Summary = "create", "Add "+item+" to "+parent
	case http.MethodPut, http.MethodPatch:
		if len(rest) == 0 {
			class.Action, class.Summary = "update", "Update "+item+"s of "+parent
		} else {
			class.Action, class.Summary = "update", "Update "+itemRef+" of "+parent
		}
	case http.MethodDelete:
		class.Action, class.Summary = "delete", "Remove "+itemRef+" from "+parent
	}
}

func auditWafSectionLabel(section string) string {
	if label, ok := auditWafSectionLabels[section]; ok {
		return label
	}
	return strings.ReplaceAll(section, "-", " ")
}

func trimAuditSegments(segs []string, from int) []string {
	if len(segs) <= from {
		return nil
	}
	return segs[from:]
}

func parseAuditID(raw string) int64 {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id < 0 {
		return 0
	}
	return id
}

func auditBodyString(body map[string]any, key string) string {
	if body == nil {
		return ""
	}
	if value, ok := body[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

var auditPastTense = map[string]string{
	"Add": "Added", "Block": "Blocked", "Change": "Changed", "Clear": "Cleared",
	"Create": "Created", "Delete": "Deleted", "Disable": "Disabled", "Duplicate": "Duplicated",
	"Enable": "Enabled", "Fork": "Forked", "Power": "Powered", "Purge": "Purged",
	"Reboot": "Rebooted", "Regenerate": "Regenerated", "Remove": "Removed", "Request": "Requested",
	"Reset": "Reset", "Revoke": "Revoked", "Start": "Started", "Stop": "Stopped",
	"Update": "Updated", "Upgrade": "Upgraded",
}

// conjugateAuditSummary turns "Delete user X" into "Deleted user X" or "Failed to delete user X".
func conjugateAuditSummary(summary string, success bool) string {
	summary = strings.TrimSpace(summary)
	if summary == "" {
		return ""
	}
	verb, rest, _ := strings.Cut(summary, " ")
	if !success {
		return "Failed to " + strings.ToLower(verb[:1]) + verb[1:] + prefixSpace(rest)
	}
	if past, ok := auditPastTense[verb]; ok {
		return past + prefixSpace(rest)
	}
	return summary
}

func prefixSpace(value string) string {
	if value == "" {
		return ""
	}
	return " " + value
}
