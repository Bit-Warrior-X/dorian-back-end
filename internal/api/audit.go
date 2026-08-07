package api

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"vue-project-backend/internal/store"
)

const (
	auditHeaderActorID    = "X-Actor-Id"
	auditHeaderActorName  = "X-Actor-Name"
	auditHeaderActorEmail = "X-Actor-Email"
	auditHeaderActorRole  = "X-Actor-Role"
)

type auditActor struct {
	UserID *int64
	Name   string
	Email  string
	Role   string
}

type auditClassification struct {
	ShouldLog    bool
	Action       string
	Category     string
	ResourceType string
	ResourceID   int64
	ResourceName string
	Details      string
}

func auditActorFromRequest(r *http.Request) auditActor {
	idRaw := strings.TrimSpace(r.Header.Get(auditHeaderActorID))
	var userID *int64
	if idRaw != "" {
		if parsed, err := strconv.ParseInt(idRaw, 10, 64); err == nil && parsed > 0 {
			userID = &parsed
		}
	}
	return auditActor{
		UserID: userID,
		Name:   strings.TrimSpace(r.Header.Get(auditHeaderActorName)),
		Email:  strings.TrimSpace(r.Header.Get(auditHeaderActorEmail)),
		Role:   strings.TrimSpace(r.Header.Get(auditHeaderActorRole)),
	}
}

func clientIPFromRequest(r *http.Request) string {
	for _, header := range []string{"X-Forwarded-For", "X-Real-IP"} {
		value := strings.TrimSpace(r.Header.Get(header))
		if value == "" {
			continue
		}
		parts := strings.Split(value, ",")
		if len(parts) > 0 {
			candidate := strings.TrimSpace(parts[0])
			if candidate != "" {
				return candidate
			}
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func writeAuditLog(ctx context.Context, audit store.AuditLogStore, input store.AuditLogInput) {
	if audit == nil {
		return
	}
	if err := audit.Create(ctx, input); err != nil {
		log.Printf("[audit] failed to write log action=%q category=%q path=%q: %v",
			input.Action, input.Category, input.Path, err)
	}
}

func auditInputFromRequest(r *http.Request, status int, class auditClassification, actor auditActor) store.AuditLogInput {
	var resourceID *int64
	if class.ResourceID > 0 {
		value := class.ResourceID
		resourceID = &value
	}
	details := class.Details
	if details == "" {
		details = strings.TrimSpace(r.Method + " " + r.URL.Path)
	}
	return store.AuditLogInput{
		Action:       class.Action,
		Category:     class.Category,
		ResourceType: class.ResourceType,
		ResourceID:   resourceID,
		ResourceName: class.ResourceName,
		ActorUserID:  actor.UserID,
		ActorName:    actor.Name,
		ActorEmail:   actor.Email,
		ActorRole:    actor.Role,
		IPAddress:    clientIPFromRequest(r),
		UserAgent:    r.UserAgent(),
		HTTPMethod:   r.Method,
		Path:         r.URL.Path,
		StatusCode:   status,
		Details:      details,
	}
}

func classifyAuditRequest(method, path string, status int) auditClassification {
	path = strings.TrimSuffix(strings.TrimSpace(path), "/")
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == http.MethodOptions {
		return auditClassification{}
	}

	if method == http.MethodGet || method == http.MethodHead {
		return auditClassification{}
	}

	if strings.HasPrefix(path, "/users") {
		return classifyCollectionMutation(method, path, "/users", "user", "user")
	}
	if strings.HasPrefix(path, "/servers/blacklist") {
		return classifyCollectionMutation(method, path, "/servers/blacklist", "blacklist", "blocked_list")
	}
	if path == "/servers" || strings.HasPrefix(path, "/servers/") {
		if path == "/servers" || path == "/servers/" {
			return classifyCollectionMutation(method, path, "/servers", "edge", "edge")
		}
		return classifyServerMutation(method, path)
	}
	if path == "/sites" || strings.HasPrefix(path, "/sites/") {
		return classifySiteMutation(method, path)
	}
	if path == "/waf-rules" || strings.HasPrefix(path, "/waf-rules/") {
		return classifyWafRuleMutation(method, path)
	}

	return auditClassification{}
}

func classifyCollectionMutation(method, path, prefix, category, resourceType string) auditClassification {
	action := mutationAction(method, path)
	if action == "" {
		return auditClassification{}
	}
	resourceID := parseLeadingResourceID(strings.TrimPrefix(path, prefix))
	resourceName := store.FormatAuditResourceLabel(category, resourceID, "")
	return auditClassification{
		ShouldLog:    true,
		Action:       action,
		Category:     category,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Details:      humanizeMutation(action, category, path),
	}
}

func classifyServerMutation(method, path string) auditClassification {
	action := mutationAction(method, path)
	if action == "" {
		return auditClassification{}
	}

	trimmed := strings.TrimPrefix(path, "/servers/")
	parts := strings.Split(trimmed, "/")
	serverID := int64(0)
	if len(parts) > 0 {
		if parsed, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
			serverID = parsed
		}
	}

	category := "edge"
	suffix := "edge settings"
	if len(parts) > 1 {
		switch parts[1] {
		case "listening-ports":
			category = "listening_port"
			suffix = "listening ports"
		case "l4":
			category = "l4"
			if len(parts) > 2 {
				suffix = "L4 · " + strings.Join(parts[2:], "/")
			} else {
				suffix = "L4 settings"
			}
		case "waf":
			category = "waf"
			if len(parts) > 2 {
				suffix = "edge WAF · " + strings.Join(parts[2:], "/")
			} else {
				suffix = "edge WAF"
			}
		default:
			suffix = strings.Join(parts[1:], "/")
		}
	}

	return auditClassification{
		ShouldLog:    true,
		Action:       action,
		Category:     category,
		ResourceType: "edge",
		ResourceID:   serverID,
		ResourceName: store.FormatAuditResourceLabel("edge", serverID, suffix),
		Details:      humanizeMutation(action, category, path),
	}
}

func classifySiteMutation(method, path string) auditClassification {
	action := mutationAction(method, path)
	if action == "" {
		return auditClassification{}
	}

	trimmed := strings.TrimPrefix(path, "/sites/")
	parts := strings.Split(trimmed, "/")
	siteID := int64(0)
	if len(parts) > 0 {
		if parsed, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
			siteID = parsed
		}
	}

	category := "site"
	suffix := "site settings"
	if len(parts) > 1 {
		switch parts[1] {
		case "upstream-servers":
			category = "origin"
			suffix = "origin servers"
		case "cache-rules":
			category = "cache"
			suffix = "cache rules"
		case "compress":
			category = "compress"
			suffix = "compression"
		case "ports":
			category = "ports"
			suffix = "edge ports"
		case "waf":
			category = "waf"
			if len(parts) > 2 {
				suffix = "site WAF · " + strings.Join(parts[2:], "/")
			} else {
				suffix = "site WAF"
			}
		default:
			suffix = strings.Join(parts[1:], "/")
		}
	}

	return auditClassification{
		ShouldLog:    true,
		Action:       action,
		Category:     category,
		ResourceType: "site",
		ResourceID:   siteID,
		ResourceName: store.FormatAuditResourceLabel("site", siteID, suffix),
		Details:      humanizeMutation(action, category, path),
	}
}

func classifyWafRuleMutation(method, path string) auditClassification {
	action := mutationAction(method, path)
	if action == "" {
		return auditClassification{}
	}
	trimmed := strings.TrimPrefix(path, "/waf-rules/")
	parts := strings.Split(trimmed, "/")
	ruleID := int64(0)
	if len(parts) > 0 && parts[0] != "" {
		if parsed, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
			ruleID = parsed
		}
	}
	suffix := "rule set"
	if len(parts) > 1 {
		suffix = strings.Join(parts[1:], "/")
	}
	return auditClassification{
		ShouldLog:    true,
		Action:       action,
		Category:     "waf_rule",
		ResourceType: "waf_rule",
		ResourceID:   ruleID,
		ResourceName: store.FormatAuditResourceLabel("WAF rule", ruleID, suffix),
		Details:      humanizeMutation(action, "WAF rule", path),
	}
}

func mutationAction(method, path string) string {
	lowerPath := strings.ToLower(path)
	if strings.Contains(lowerPath, "batch-delete") {
		return "batch_delete"
	}
	switch method {
	case http.MethodPost:
		if strings.Contains(lowerPath, "/duplicate") {
			return "duplicate"
		}
		if strings.Contains(lowerPath, "/fork") {
			return "fork"
		}
		return "create"
	case http.MethodPut, http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	default:
		return ""
	}
}

func parseLeadingResourceID(remainder string) int64 {
	remainder = strings.TrimPrefix(remainder, "/")
	if remainder == "" {
		return 0
	}
	parts := strings.Split(remainder, "/")
	if len(parts) == 0 {
		return 0
	}
	parsed, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func humanizeMutation(action, category, path string) string {
	switch action {
	case "create":
		return "Created " + category
	case "update":
		return "Updated " + category
	case "delete":
		return "Deleted " + category
	case "batch_delete":
		return "Batch deleted " + category
	case "duplicate":
		return "Duplicated " + category
	case "fork":
		return "Forked " + category
	default:
		return strings.ToUpper(action) + " " + path
	}
}

func withAuditLogging(audit store.AuditLogStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 0}
		next.ServeHTTP(rec, r)

		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}

		class := classifyAuditRequest(r.Method, r.URL.Path, status)
		if !class.ShouldLog {
			return
		}
		if status >= 500 {
			return
		}

		actor := auditActorFromRequest(r)
		input := auditInputFromRequest(r, status, class, actor)
		writeAuditLog(r.Context(), audit, input)
	})
}

func auditLogsHandler(audit store.AuditLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				limit = parsed
			}
		}

		filter := store.AuditLogFilter{
			Limit:    limit,
			Category: strings.TrimSpace(r.URL.Query().Get("category")),
			Action:   strings.TrimSpace(r.URL.Query().Get("action")),
			Search:   strings.TrimSpace(r.URL.Query().Get("search")),
		}
		if raw := strings.TrimSpace(r.URL.Query().Get("actorUserId")); raw != "" {
			if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
				filter.ActorUserID = parsed
			}
		}

		items, err := audit.List(r.Context(), filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load audit history")
			return
		}
		if items == nil {
			items = []store.AuditLog{}
		}
		writeJSON(w, http.StatusOK, items)
	}
}

func logoutHandler(audit store.AuditLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var payload struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)

		actor := auditActorFromRequest(r)
		details := "User signed out"
		switch strings.ToLower(strings.TrimSpace(payload.Reason)) {
		case "idle":
			details = "Session expired due to inactivity"
		case "manual":
			details = "User signed out manually"
		}

		writeAuditLog(r.Context(), audit, auditInputFromRequest(r, http.StatusNoContent, auditClassification{
			ShouldLog:    true,
			Action:       "logout",
			Category:     "auth",
			ResourceType: "session",
			Details:      details,
		}, actor))

		w.WriteHeader(http.StatusNoContent)
	}
}

func logLoginAttempt(ctx context.Context, audit store.AuditLogStore, r *http.Request, user store.User, success bool, status int, details string) {
	if audit == nil {
		return
	}
	action := "login"
	if !success {
		action = "login_failed"
	}
	actor := auditActor{
		Name:  user.Name,
		Email: user.Email,
		Role:  user.Role,
	}
	if user.ID > 0 {
		id := user.ID
		actor.UserID = &id
	}
	if !success && user.Email != "" {
		actor.Email = user.Email
	}
	writeAuditLog(ctx, audit, auditInputFromRequest(r, status, auditClassification{
		ShouldLog:    true,
		Action:       action,
		Category:     "auth",
		ResourceType: "session",
		Details:      details,
	}, actor))
}
