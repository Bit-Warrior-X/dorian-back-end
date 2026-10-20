package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"vue-project-backend/internal/auth"
	"vue-project-backend/internal/config"
	"vue-project-backend/internal/mailer"
	"vue-project-backend/internal/store"
)

const (
	inviteLinkTTL     = 7 * 24 * time.Hour
	adminResetLinkTTL = 24 * time.Hour
	selfResetLinkTTL  = time.Hour
	minPasswordLength = 8
)

// accountServices groups the stores behind sign-in sessions, the 2FA policy,
// and invite / password-reset links.
type accountServices struct {
	cfg      config.Config
	users    store.UserStore
	mfa      store.MFAStore
	sessions store.AuthSessionStore
	settings store.PanelSettingsStore
	tokens   store.UserTokenStore
	mailer   *mailer.Mailer
	audit    store.AuditLogStore
	limiter  *resetRequestLimiter
}

func newAccountServices(cfg config.Config, users store.UserStore, mfa store.MFAStore, sessions store.AuthSessionStore, settings store.PanelSettingsStore, tokens store.UserTokenStore, audit store.AuditLogStore) *accountServices {
	return &accountServices{
		cfg:      cfg,
		users:    users,
		mfa:      mfa,
		sessions: sessions,
		settings: settings,
		tokens:   tokens,
		mailer:   mailer.New(cfg),
		audit:    audit,
		limiter:  newResetRequestLimiter(),
	}
}

func (a *accountServices) sessionTTL(remember bool) time.Duration {
	if remember && a.cfg.RememberMeTTLDays > 0 {
		return time.Duration(a.cfg.RememberMeTTLDays) * 24 * time.Hour
	}
	hours := a.cfg.JWTTTLHours
	if hours <= 0 {
		hours = 24
	}
	return time.Duration(hours) * time.Hour
}

func (a *accountServices) requireMFAPolicy(ctx context.Context) string {
	if a.settings == nil {
		return store.RequireMFAOff
	}
	value, err := a.settings.Get(ctx, store.SettingRequireMFA)
	if err != nil {
		return store.RequireMFAOff
	}
	return store.NormalizeRequireMFA(value)
}

func (a *accountServices) mfaSetupRequired(ctx context.Context, user store.User) bool {
	if !store.RequireMFAApplies(a.requireMFAPolicy(ctx), user.Role) {
		return false
	}
	enabled, err := mfaRequiredForUser(ctx, a.mfa, user.ID)
	return err == nil && !enabled
}

func (a *accountServices) issueSession(r *http.Request, user store.User, method string, remember bool) (string, store.AuthSession, error) {
	ttl := a.sessionTTL(remember)
	session, err := a.sessions.Create(r.Context(), store.AuthSessionCreateInput{
		UserID:    user.ID,
		Method:    method,
		Remember:  remember,
		IPAddress: clientIPFromRequest(r),
		UserAgent: r.UserAgent(),
		TTL:       ttl,
	})
	if err != nil {
		return "", store.AuthSession{}, fmt.Errorf("create session: %w", err)
	}
	token, err := auth.IssueUserToken(auth.UserIdentity{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Role:      user.Role,
		SessionID: session.ID,
	}, a.cfg.JWTSecret, ttl)
	if err != nil {
		_, _ = a.sessions.Revoke(r.Context(), user.ID, session.ID)
		return "", store.AuthSession{}, err
	}
	return token, session, nil
}

// writeSessionResponse issues a session and answers the login request.
func (a *accountServices) writeSessionResponse(w http.ResponseWriter, r *http.Request, user store.User, method string, remember bool) bool {
	token, session, err := a.issueSession(r, user, method, remember)
	if err != nil {
		log.Printf("[auth] failed to issue session for user=%d: %v", user.ID, err)
		writeError(w, http.StatusInternalServerError, "failed to issue session token")
		return false
	}
	writeJSON(w, http.StatusOK, loginResponse{
		Token:            token,
		User:             userShape{ID: user.ID, Email: user.Email, Role: user.Role, Name: user.Name},
		Remember:         session.Remember,
		ExpiresAt:        session.ExpiresAt,
		MFASetupRequired: a.mfaSetupRequired(r.Context(), user),
	})
	return true
}

func (a *accountServices) frontendBase(r *http.Request) string {
	if base := strings.TrimRight(strings.TrimSpace(a.cfg.FrontendURL), "/"); base != "" {
		return base
	}
	scheme := "https"
	if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); proto != "" {
		scheme = strings.ToLower(strings.Split(proto, ",")[0])
	} else if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// passwordLink keeps the secret in the URL fragment so it never reaches access
// logs or Referer headers.
func (a *accountServices) passwordLink(r *http.Request, purpose, secret string) string {
	params := url.Values{}
	params.Set("token", secret)
	return a.frontendBase(r) + "/login/set-password?purpose=" + url.QueryEscape(purpose) + "#" + params.Encode()
}

func (a *accountServices) sendLinkEmail(to, name, purpose, link string, expires time.Time) error {
	greeting := "Hello"
	if strings.TrimSpace(name) != "" {
		greeting = "Hello " + strings.TrimSpace(name)
	}
	var subject, intro string
	switch purpose {
	case store.UserTokenInvite:
		subject = "You're invited to the Dorian console"
		intro = "An administrator invited you to the Dorian console. Choose a password to activate your account:"
	default:
		subject = "Reset your Dorian password"
		intro = "We received a request to reset your Dorian console password. Choose a new password here:"
	}
	body := fmt.Sprintf("%s,\n\n%s\n\n%s\n\nThis link works once and expires %s UTC.\nIf you did not expect this email, you can ignore it.\n\n— Dorian",
		greeting, intro, link, expires.UTC().Format("Jan 2, 2006 15:04"))
	return a.mailer.Send(to, subject, body)
}

func validNewPassword(password string) error {
	if len([]rune(strings.TrimSpace(password))) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minPasswordLength)
	}
	return nil
}

func pathUserID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// --- /auth/me, /auth/options -------------------------------------------------

func meHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := AuthPrincipalFromContext(r.Context())
		if !ok || principal.UserID <= 0 {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized", Message: "Authentication required."})
			return
		}
		user, err := a.users.FindByID(r.Context(), principal.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load account")
			return
		}
		policy := a.requireMFAPolicy(r.Context())
		out := map[string]any{
			"user":             userShape{ID: user.ID, Email: user.Email, Role: user.Role, Name: user.Name},
			"authKind":         principal.AuthKind,
			"mfaEnabled":       principal.MFAEnabled,
			"requireMfa":       policy,
			"mfaSetupRequired": store.RequireMFAApplies(policy, user.Role) && !principal.MFAEnabled,
		}
		if principal.SessionID != "" {
			if lookup, err := a.sessions.LookupActive(r.Context(), principal.SessionID); err == nil {
				out["session"] = lookup.Session
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func authOptionsHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"emailDelivery":  a.mailer.Enabled() && strings.TrimSpace(a.cfg.FrontendURL) != "",
			"rememberMeDays": a.cfg.RememberMeTTLDays,
			"sessionHours":   a.cfg.JWTTTLHours,
		})
	}
}

// --- sessions ----------------------------------------------------------------

type sessionView struct {
	store.AuthSession
	Current bool `json:"current"`
}

func sessionViews(items []store.AuthSession, currentID string) []sessionView {
	out := make([]sessionView, 0, len(items))
	for _, item := range items {
		out = append(out, sessionView{AuthSession: item, Current: item.ID == currentID})
	}
	return out
}

func sessionsHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := requireInteractiveSession(w, r)
		if !ok {
			return
		}
		switch r.Method {
		case http.MethodGet:
			items, err := a.sessions.ListActiveForUser(r.Context(), principal.UserID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load sessions")
				return
			}
			writeJSON(w, http.StatusOK, sessionViews(items, principal.SessionID))
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func sessionDetailHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := requireInteractiveSession(w, r)
		if !ok {
			return
		}
		rest := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/api/v1"), "/auth/sessions/")
		rest = strings.Trim(rest, "/")
		if rest == "revoke-others" {
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			count, err := a.sessions.RevokeAllForUser(r.Context(), principal.UserID, principal.SessionID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to sign out other sessions")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"revoked": count})
			return
		}
		if rest == "" || strings.Contains(rest, "/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if r.Method != http.MethodDelete {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		revoked, err := a.sessions.Revoke(r.Context(), principal.UserID, rest)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to sign out session")
			return
		}
		if !revoked {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func adminUserSessionsHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUserID(r)
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		items, err := a.sessions.ListActiveForUser(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load sessions")
			return
		}
		principal, _ := AuthPrincipalFromContext(r.Context())
		writeJSON(w, http.StatusOK, sessionViews(items, principal.SessionID))
	}
}

func adminRevokeUserSessionsHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUserID(r)
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		principal, _ := AuthPrincipalFromContext(r.Context())
		except := ""
		if principal.UserID == id {
			except = principal.SessionID
		}
		count, err := a.sessions.RevokeAllForUser(r.Context(), id, except)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to sign out user")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"revoked": count})
	}
}

// --- security settings ---------------------------------------------------------

func securitySettingsHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]any{
				"requireMfa":     a.requireMFAPolicy(r.Context()),
				"emailDelivery":  a.mailer.Enabled(),
				"sessionHours":   a.cfg.JWTTTLHours,
				"rememberMeDays": a.cfg.RememberMeTTLDays,
			})
		case http.MethodPut, http.MethodPatch:
			principal, ok := requireInteractiveSession(w, r)
			if !ok {
				return
			}
			var payload struct {
				RequireMFA string `json:"requireMfa"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			raw := strings.ToLower(strings.TrimSpace(payload.RequireMFA))
			policy := store.NormalizeRequireMFA(raw)
			if raw != policy {
				writeError(w, http.StatusBadRequest, "requireMfa must be off, admins, or all")
				return
			}
			if policy != store.RequireMFAOff && !principal.MFAEnabled {
				writeJSON(w, http.StatusConflict, errorResponse{
					Error:   "mfa_not_enabled",
					Message: "Turn on two-factor authentication for your own account before requiring it.",
				})
				return
			}
			if err := a.settings.Set(r.Context(), store.SettingRequireMFA, policy, principal.UserID); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to save security settings")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"requireMfa":     policy,
				"emailDelivery":  a.mailer.Enabled(),
				"sessionHours":   a.cfg.JWTTTLHours,
				"rememberMeDays": a.cfg.RememberMeTTLDays,
			})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func apiTokenScopesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeJSON(w, http.StatusOK, apiTokenScopeCatalog)
	}
}

// --- invite / reset links -----------------------------------------------------

type passwordLinkResponse struct {
	Link      string    `json:"link"`
	Emailed   bool      `json:"emailed"`
	EmailErr  string    `json:"emailError,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (a *accountServices) createLink(r *http.Request, user store.User, purpose string, ttl time.Duration) (passwordLinkResponse, error) {
	principal, _ := AuthPrincipalFromContext(r.Context())
	secret, expires, err := a.tokens.Issue(r.Context(), user.ID, purpose, ttl, principal.UserID)
	if err != nil {
		return passwordLinkResponse{}, err
	}
	link := a.passwordLink(r, purpose, secret)
	out := passwordLinkResponse{Link: link, ExpiresAt: expires}
	if a.mailer.Enabled() {
		if err := a.sendLinkEmail(user.Email, user.Name, purpose, link, expires); err != nil {
			log.Printf("[account] %s email to user=%d failed: %v", purpose, user.ID, err)
			out.EmailErr = "Email could not be sent. Share the link manually."
		} else {
			out.Emailed = true
		}
	}
	return out, nil
}

func (a *accountServices) issueLinkFor(w http.ResponseWriter, r *http.Request, user store.User, purpose string, ttl time.Duration) {
	out, err := a.createLink(r, user, purpose, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create link")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// lastActiveAdminChange reports whether changing target (to role/status, or
// deleting it) would leave no active Admin.
func (a *accountServices) lastActiveAdminChange(ctx context.Context, target store.User, nextRole, nextStatus string, deleting bool) (bool, error) {
	if !strings.EqualFold(target.Role, "Admin") || !strings.EqualFold(target.Status, "Active") {
		return false, nil
	}
	if !deleting && strings.EqualFold(nextRole, "Admin") && strings.EqualFold(nextStatus, "Active") {
		return false, nil
	}
	list, err := a.users.List(ctx)
	if err != nil {
		return false, err
	}
	for _, user := range list {
		if user.ID != target.ID && strings.EqualFold(user.Role, "Admin") && strings.EqualFold(user.Status, "Active") {
			return false, nil
		}
	}
	return true, nil
}

func writeLastAdminConflict(w http.ResponseWriter) {
	writeJSON(w, http.StatusConflict, errorResponse{
		Error:   "last_admin",
		Message: "At least one active Admin is required. Promote another user first.",
	})
}

func userInviteHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUserID(r)
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		user, err := a.users.FindByID(r.Context(), id)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusNotFound, "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to load user")
			return
		}
		if strings.EqualFold(user.Status, "Block") {
			writeError(w, http.StatusConflict, "unblock this user before inviting them")
			return
		}
		if user.HasPassword && strings.EqualFold(user.Status, "Active") {
			writeError(w, http.StatusConflict, "this user has already set a password; send a password reset link instead")
			return
		}
		a.issueLinkFor(w, r, user, store.UserTokenInvite, inviteLinkTTL)
	}
}

func userResetLinkHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUserID(r)
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		user, err := a.users.FindByID(r.Context(), id)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusNotFound, "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to load user")
			return
		}
		a.issueLinkFor(w, r, user, store.UserTokenPasswordReset, adminResetLinkTTL)
	}
}

// resetRequestLimiter caps self-service reset emails per address and per IP.
type resetRequestLimiter struct {
	mu      sync.Mutex
	byEmail map[string]time.Time
	byIP    map[string][]time.Time
}

func newResetRequestLimiter() *resetRequestLimiter {
	return &resetRequestLimiter{byEmail: map[string]time.Time{}, byIP: map[string][]time.Time{}}
}

func (l *resetRequestLimiter) allow(email, ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if last, ok := l.byEmail[email]; ok && now.Sub(last) < 2*time.Minute {
		return false
	}
	recent := l.byIP[ip][:0]
	for _, at := range l.byIP[ip] {
		if now.Sub(at) < time.Hour {
			recent = append(recent, at)
		}
	}
	if len(recent) >= 10 {
		l.byIP[ip] = recent
		return false
	}
	l.byEmail[email] = now
	l.byIP[ip] = append(recent, now)
	return true
}

func forgotPasswordHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var payload struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		email := strings.ToLower(strings.TrimSpace(payload.Email))
		if email == "" {
			writeError(w, http.StatusBadRequest, "email is required")
			return
		}
		// Without a fixed FRONTEND_URL the link would be built from the Host header,
		// which a requester controls.
		enabled := a.mailer.Enabled() && strings.TrimSpace(a.cfg.FrontendURL) != ""
		respond := func() {
			writeJSON(w, http.StatusAccepted, map[string]any{"emailDelivery": enabled})
		}
		if !enabled || !a.limiter.allow(email, clientIPFromRequest(r), time.Now()) {
			respond()
			return
		}
		user, err := a.users.FindByEmail(r.Context(), email)
		if err != nil || strings.EqualFold(user.Status, "Block") {
			respond()
			return
		}
		purpose := store.UserTokenPasswordReset
		ttl := selfResetLinkTTL
		if !user.HasPassword && strings.EqualFold(user.Status, "Waiting") {
			purpose, ttl = store.UserTokenInvite, inviteLinkTTL
		}
		secret, expires, err := a.tokens.Issue(r.Context(), user.ID, purpose, ttl, 0)
		if err == nil {
			link := a.passwordLink(r, purpose, secret)
			go func() {
				if err := a.sendLinkEmail(user.Email, user.Name, purpose, link, expires); err != nil {
					log.Printf("[account] reset email to user=%d failed: %v", user.ID, err)
				}
			}()
		}
		respond()
	}
}

func passwordTokenHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var payload struct {
			Token   string `json:"token"`
			Purpose string `json:"purpose"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		peek, err := a.tokens.Peek(r.Context(), payload.Token, strings.TrimSpace(payload.Purpose))
		if err != nil {
			writeLinkInvalid(w, err)
			return
		}
		writeJSON(w, http.StatusOK, peek)
	}
}

func writeLinkInvalid(w http.ResponseWriter, err error) {
	if err != nil && !store.IsNotFound(err) {
		writeError(w, http.StatusInternalServerError, "failed to verify link")
		return
	}
	writeJSON(w, http.StatusGone, errorResponse{
		Error:   "link_invalid",
		Message: "This link has expired or was already used. Ask an administrator for a new one.",
	})
}

func completePasswordHandler(a *accountServices) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var payload struct {
			Token    string `json:"token"`
			Purpose  string `json:"purpose"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		purpose := strings.TrimSpace(payload.Purpose)
		if err := validNewPassword(payload.Password); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(strings.TrimSpace(payload.Password)) > store.MaxPasswordBytes {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("password must be at most %d bytes", store.MaxPasswordBytes))
			return
		}
		peek, err := a.tokens.Consume(r.Context(), payload.Token, purpose)
		if err != nil {
			writeLinkInvalid(w, err)
			return
		}
		if err := a.users.SetPassword(r.Context(), peek.UserID, payload.Password, purpose == store.UserTokenInvite); err != nil {
			if errors.Is(err, store.ErrPasswordTooLong) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to set password")
			return
		}
		if _, err := a.sessions.RevokeAllForUser(r.Context(), peek.UserID, ""); err != nil {
			log.Printf("[account] revoke sessions after password set user=%d: %v", peek.UserID, err)
		}
		userID := peek.UserID
		action, details := "password_reset", "Password reset with a one-time link"
		if purpose == store.UserTokenInvite {
			action, details = "invite_accept", "Accepted invite and set a password"
		}
		writeAuditLog(r.Context(), a.audit, auditInputFromRequest(r, http.StatusNoContent, auditClassification{
			ShouldLog:    true,
			Action:       action,
			Category:     "auth",
			ResourceType: "user",
			ResourceID:   userID,
			ResourceName: peek.Email,
			Details:      details,
		}, auditActor{UserID: &userID, Name: peek.Name, Email: peek.Email}))
		w.WriteHeader(http.StatusNoContent)
	}
}

func registerAccountRoutes(mux *http.ServeMux, a *accountServices) {
	for _, prefix := range []string{"", "/api/v1"} {
		mux.HandleFunc(prefix+"/auth/me", meHandler(a))
		mux.HandleFunc(prefix+"/auth/options", authOptionsHandler(a))
		mux.HandleFunc(prefix+"/auth/sessions", sessionsHandler(a))
		mux.HandleFunc(prefix+"/auth/sessions/", sessionDetailHandler(a))
		mux.HandleFunc(prefix+"/auth/api-token-scopes", apiTokenScopesHandler())
		mux.HandleFunc(prefix+"/auth/password/forgot", forgotPasswordHandler(a))
		mux.HandleFunc(prefix+"/auth/password/token", passwordTokenHandler(a))
		mux.HandleFunc(prefix+"/auth/password/complete", completePasswordHandler(a))
		mux.HandleFunc(prefix+"/settings/security", requireAdmin(securitySettingsHandler(a)))
		mux.HandleFunc("GET "+prefix+"/users/{id}/sessions", requireAdmin(adminUserSessionsHandler(a)))
		mux.HandleFunc("POST "+prefix+"/users/{id}/sessions/revoke", requireAdmin(adminRevokeUserSessionsHandler(a)))
		mux.HandleFunc("POST "+prefix+"/users/{id}/invite", requireAdmin(userInviteHandler(a)))
		mux.HandleFunc("POST "+prefix+"/users/{id}/password-reset", requireAdmin(userResetLinkHandler(a)))
	}
}
