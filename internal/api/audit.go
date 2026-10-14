package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"vue-project-backend/internal/store"
)

const (
	auditMaxRequestBody  = 1 << 20
	auditMaxResponseBody = 64 << 10
)

type auditActor struct {
	UserID *int64
	Name   string
	Email  string
	Role   string
}

// auditActorFromRequest returns the authenticated principal. Client-supplied identity
// headers are deliberately not trusted.
func auditActorFromRequest(r *http.Request) auditActor {
	principal, ok := AuthPrincipalFromContext(r.Context())
	if !ok || principal.UserID <= 0 {
		return auditActor{}
	}
	id := principal.UserID
	return auditActor{
		UserID: &id,
		Name:   principal.Name,
		Email:  principal.Email,
		Role:   principal.Role,
	}
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

// withAuditLogging records mutating panel requests. It must run inside withAuth so
// the authenticated principal is available on the request context.
func withAuditLogging(audit store.AuditLogStore, resolver *auditResolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		class := classifyAuditRequest(r.Method, r.URL.Path)
		if !class.ShouldLog || audit == nil {
			next.ServeHTTP(w, r)
			return
		}

		var body any
		if raw := readAuditRequestBody(r); len(bytes.TrimSpace(raw)) > 0 {
			_ = json.Unmarshal(raw, &body)
		}

		actor := auditActorFromRequest(r)
		if class.SelfTarget && actor.UserID != nil {
			class.ResourceID = *actor.UserID
		}
		before, hasBefore := resolver.loadTarget(r.Context(), class.ResourceType, class.ResourceID)

		rec := &auditRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}

		ctx := context.WithoutCancel(r.Context())
		entry := buildAuditEntry(ctx, resolver, r, status, class, actor, body, before, hasBefore, rec.body.Bytes())
		writeAuditLog(ctx, audit, entry)
	})
}

func buildAuditEntry(
	ctx context.Context,
	res *auditResolver,
	r *http.Request,
	status int,
	class auditClassification,
	actor auditActor,
	body any,
	before auditTarget,
	hasBefore bool,
	response []byte,
) store.AuditLogInput {
	success := status < http.StatusBadRequest
	bodyMap, _ := body.(map[string]any)
	var responseMap map[string]any
	if len(response) > 0 {
		_ = json.Unmarshal(response, &responseMap)
	}

	resourceID := class.ResourceID
	if resourceID == 0 && success {
		if id, ok := responseMap["id"].(float64); ok && id > 0 {
			resourceID = int64(id)
		}
	}

	wantsDiff := class.Diff || len(class.DiffFields) > 0
	var after auditTarget
	hasAfter := false
	if wantsDiff && success {
		after, hasAfter = res.loadTarget(ctx, class.ResourceType, resourceID)
	}

	label := class.ResourceName
	switch {
	case class.SelfTarget:
		label = auditUserLabel(actor.Name, actor.Email)
	case hasBefore:
		label = before.Label
	case hasAfter:
		label = after.Label
	}
	if label == "" {
		label = auditLabelFromValues(class.ResourceType, responseMap)
	}
	if label == "" {
		label = auditLabelFromValues(class.ResourceType, bodyMap)
	}
	if label == "" && resourceID > 0 {
		label = "#" + strconv.FormatInt(resourceID, 10)
	}

	summary := class.Summary
	if class.Describe != nil {
		summary = class.Describe(bodyMap)
	}
	action := class.Action

	var lines []string
	switch {
	case wantsDiff && hasBefore && hasAfter:
		lines = res.diffLines(ctx, before.State, after.State, bodyMap, class.DiffFields)
		if len(lines) == 0 && class.Diff && !class.BodyValues {
			lines = []string{"No field values changed"}
		}
	case class.Diff:
		lines = res.valueLines(ctx, body)
	}
	if class.BodyValues {
		lines = append(lines, res.valueLines(ctx, body)...)
	}

	if success && class.ResourceType == "user" && action == "update" &&
		len(lines) == 1 && lines[0] == auditFieldLabel("password")+": changed" {
		action = "password_change"
		if actor.UserID != nil && *actor.UserID == resourceID {
			summary = "Change own password"
		} else {
			summary = "Reset password of user {target}"
		}
		lines = nil
	}

	if !success {
		lines = append(lines, auditErrorLine(status, responseMap))
	}

	text := conjugateAuditSummary(summary, success)
	if label != "" {
		text = strings.ReplaceAll(text, "{target}", `"`+label+`"`)
	} else {
		text = strings.ReplaceAll(strings.ReplaceAll(text, " {target}", ""), "{target}", "")
	}
	var details strings.Builder
	details.WriteString(text)
	for _, line := range lines {
		details.WriteString("\n• ")
		details.WriteString(line)
	}

	class.Action = action
	class.ResourceID = resourceID
	class.ResourceName = label
	class.Details = details.String()
	return auditInputFromRequest(r, status, class, actor)
}

func auditErrorLine(status int, response map[string]any) string {
	reason := auditBodyString(response, "message")
	if reason == "" {
		reason = auditBodyString(response, "error")
	}
	statusText := fmt.Sprintf("HTTP %d %s", status, http.StatusText(status))
	if reason == "" || strings.EqualFold(reason, http.StatusText(status)) {
		return "Error: " + statusText
	}
	return "Error: " + truncateAuditValue(reason) + " (" + statusText + ")"
}

// readAuditRequestBody buffers the request body so it can be inspected and still
// be read by the handler. Bodies above the limit are passed through unparsed.
func readAuditRequestBody(r *http.Request) []byte {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	original := r.Body
	data, err := io.ReadAll(io.LimitReader(original, auditMaxRequestBody+1))
	if err != nil || len(data) > auditMaxRequestBody {
		r.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(data), original), Closer: original}
		return nil
	}
	r.Body = readCloser{Reader: bytes.NewReader(data), Closer: original}
	return data
}

type readCloser struct {
	io.Reader
	io.Closer
}

// auditRecorder captures the status and the start of the response body.
type auditRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (a *auditRecorder) WriteHeader(code int) {
	if a.status == 0 {
		a.status = code
	}
	a.ResponseWriter.WriteHeader(code)
}

func (a *auditRecorder) Write(p []byte) (int, error) {
	if a.status == 0 {
		a.status = http.StatusOK
	}
	if room := auditMaxResponseBody - a.body.Len(); room > 0 {
		if len(p) > room {
			a.body.Write(p[:room])
		} else {
			a.body.Write(p)
		}
	}
	return a.ResponseWriter.Write(p)
}

func (a *auditRecorder) Flush() {
	if f, ok := a.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (a *auditRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := a.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("responseWriter does not support hijacking")
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
			Limit:     limit,
			Category:  strings.TrimSpace(r.URL.Query().Get("category")),
			Action:    strings.TrimSpace(r.URL.Query().Get("action")),
			Search:    strings.TrimSpace(r.URL.Query().Get("search")),
			IPAddress: strings.TrimSpace(r.URL.Query().Get("ip")),
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
