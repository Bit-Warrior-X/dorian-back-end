package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/auth"
	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

const (
	mfaChallengeTTL = 5 * time.Minute
	totpIssuer      = "Dorian"
)

type loginMFARequiredResponse struct {
	MFARequired bool   `json:"mfaRequired"`
	MFAToken    string `json:"mfaToken"`
}

// loginRetryAfter fails open: a Redis outage must not lock every operator out.
func loginRetryAfter(ctx context.Context, throttle store.LoginThrottleStore, ip, account string) time.Duration {
	if throttle == nil {
		return 0
	}
	wait, err := throttle.RetryAfter(ctx, ip, account)
	if err != nil {
		log.Printf("[auth] login throttle check failed: %v", err)
		return 0
	}
	return wait
}

func recordLoginFailure(ctx context.Context, throttle store.LoginThrottleStore, ip, account string) {
	if throttle == nil {
		return
	}
	if err := throttle.RecordFailure(ctx, ip, account); err != nil {
		log.Printf("[auth] login throttle record failed: %v", err)
	}
}

func recordLoginSuccess(ctx context.Context, throttle store.LoginThrottleStore, account string) {
	if throttle == nil {
		return
	}
	if err := throttle.RecordSuccess(ctx, account); err != nil {
		log.Printf("[auth] login throttle reset failed: %v", err)
	}
}

func writeTooManyAttempts(w http.ResponseWriter, wait time.Duration) {
	seconds := int(math.Ceil(wait.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	minutes := int(math.Ceil(float64(seconds) / 60))
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeJSON(w, http.StatusTooManyRequests, errorResponse{
		Error:   "too_many_attempts",
		Message: fmt.Sprintf("Too many failed sign-in attempts. Try again in %d minute(s).", minutes),
	})
}

// mfaRequiredForUser reports whether userID must pass a second factor. A missing
// migration is treated as "not enrolled" so login keeps working before rollout.
func mfaRequiredForUser(ctx context.Context, mfa store.MFAStore, userID int64) (bool, error) {
	if mfa == nil {
		return false, nil
	}
	status, err := mfa.Status(ctx, userID)
	if err != nil {
		if store.IsMFAUnavailable(err) {
			return false, nil
		}
		return false, err
	}
	return status.Enabled, nil
}

// verifySecondFactor accepts a 6-digit TOTP code or an unused recovery code.
func verifySecondFactor(ctx context.Context, mfa store.MFAStore, userID int64, code string) (bool, string, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return false, "", nil
	}
	compact := strings.ReplaceAll(code, " ", "")
	if len(compact) == 6 && strings.Trim(compact, "0123456789") == "" {
		secret, lastStep, err := mfa.Secret(ctx, userID)
		if err != nil || secret == "" {
			return false, "", err
		}
		step, ok := auth.ValidateTOTP(secret, compact, time.Now(), lastStep)
		if !ok {
			return false, "", nil
		}
		advanced, err := mfa.AdvanceStep(ctx, userID, step)
		return advanced, "authenticator code", err
	}
	ok, err := mfa.ConsumeRecoveryCode(ctx, userID, code)
	return ok, "recovery code", err
}

func loginMFAHandler(cfg config.Config, account *accountServices, users store.UserStore, mfa store.MFAStore, throttle store.LoginThrottleStore, auditLogs store.AuditLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var payload struct {
			MFAToken string `json:"mfaToken"`
			Code     string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		challenge, err := auth.ParseMFAChallenge(payload.MFAToken, cfg.JWTSecret)
		userID := challenge.UserID
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error:   "mfa_challenge_expired",
				Message: "Your sign-in session expired. Please sign in again.",
			})
			return
		}
		user, err := users.FindByID(r.Context(), userID)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error:   "mfa_challenge_expired",
				Message: "Your sign-in session expired. Please sign in again.",
			})
			return
		}
		if !strings.EqualFold(user.Status, "Active") {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:   "forbidden",
				Message: "Your account is not active. Please contact an administrator.",
			})
			return
		}

		ip := clientIPFromRequest(r)
		if wait := loginRetryAfter(r.Context(), throttle, ip, user.Email); wait > 0 {
			logLoginAttempt(r.Context(), auditLogs, r, user, false, http.StatusTooManyRequests, "Two-factor attempt while locked out")
			writeTooManyAttempts(w, wait)
			return
		}

		ok, method, err := verifySecondFactor(r.Context(), mfa, user.ID, payload.Code)
		if err != nil {
			log.Printf("[auth] 2fa verification failed user=%d: %v", user.ID, err)
			writeError(w, http.StatusInternalServerError, "failed to verify two-factor code")
			return
		}
		if !ok {
			recordLoginFailure(r.Context(), throttle, ip, user.Email)
			logLoginAttempt(r.Context(), auditLogs, r, user, false, http.StatusUnauthorized, "Invalid two-factor code")
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error:   "invalid_mfa_code",
				Message: "Invalid or already used code. Please try again.",
			})
			return
		}

		signInMethod := challenge.Method
		if signInMethod == "" {
			signInMethod = "password"
		}
		if account.writeSessionResponse(w, r, user, signInMethod+"+2fa", challenge.Remember) {
			recordLoginSuccess(r.Context(), throttle, user.Email)
			logLoginAttempt(r.Context(), auditLogs, r, user, true, http.StatusOK, "Successful login (2FA via "+method+")")
		}
	}
}

// requireInteractiveSession blocks API tokens from managing 2FA so a leaked
// automation token cannot switch off the second factor.
func requireInteractiveSession(w http.ResponseWriter, r *http.Request) (AuthPrincipal, bool) {
	principal, ok := AuthPrincipalFromContext(r.Context())
	if !ok || principal.UserID <= 0 {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized", Message: "Authentication required."})
		return AuthPrincipal{}, false
	}
	if principal.AuthKind != authKindJWT {
		writeJSON(w, http.StatusForbidden, errorResponse{
			Error:   "forbidden",
			Message: "Two-factor settings can only be changed from a signed-in console session.",
		})
		return AuthPrincipal{}, false
	}
	return principal, true
}

func writeMFAStoreError(w http.ResponseWriter, err error, fallback string) {
	if store.IsMFAUnavailable(err) {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if store.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeError(w, http.StatusInternalServerError, fallback)
}

func mfaStatusHandler(mfa store.MFAStore) http.HandlerFunc {
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
		status, err := mfa.Status(r.Context(), principal.UserID)
		if err != nil {
			writeMFAStoreError(w, err, "failed to load two-factor status")
			return
		}
		writeJSON(w, http.StatusOK, status)
	}
}

func mfaSetupHandler(mfa store.MFAStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := requireInteractiveSession(w, r)
		if !ok {
			return
		}
		status, err := mfa.Status(r.Context(), principal.UserID)
		if err != nil {
			writeMFAStoreError(w, err, "failed to load two-factor status")
			return
		}
		if status.Enabled {
			writeError(w, http.StatusConflict, "two-factor authentication is already enabled")
			return
		}
		secret, err := auth.GenerateTOTPSecret()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to generate secret")
			return
		}
		if err := mfa.SetPendingSecret(r.Context(), principal.UserID, secret); err != nil {
			writeMFAStoreError(w, err, "failed to start two-factor setup")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"secret":     secret,
			"otpauthUrl": auth.TOTPProvisioningURI(totpIssuer, principal.Email, secret),
		})
	}
}

func mfaEnableHandler(mfa store.MFAStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := requireInteractiveSession(w, r)
		if !ok {
			return
		}
		var payload struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		pending, err := mfa.PendingSecret(r.Context(), principal.UserID)
		if err != nil {
			writeMFAStoreError(w, err, "failed to load two-factor setup")
			return
		}
		if pending == "" {
			writeError(w, http.StatusBadRequest, "start two-factor setup first")
			return
		}
		step, valid := auth.ValidateTOTP(pending, payload.Code, time.Now(), 0)
		if !valid {
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error:   "invalid_mfa_code",
				Message: "That code did not match. Check your authenticator app's clock and try again.",
			})
			return
		}
		codes, err := mfa.Enable(r.Context(), principal.UserID, pending, step)
		if err != nil {
			writeMFAStoreError(w, err, "failed to enable two-factor authentication")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
	}
}

func mfaDisableHandler(account *accountServices, mfa store.MFAStore, throttle store.LoginThrottleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := requireInteractiveSession(w, r)
		if !ok {
			return
		}
		if store.RequireMFAApplies(account.requireMFAPolicy(r.Context()), principal.Role) {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error:   "mfa_required_by_policy",
				Message: "Your organization requires two-factor authentication, so it cannot be turned off.",
			})
			return
		}
		if !verifyCodeForSensitiveMFAChange(w, r, mfa, throttle, principal) {
			return
		}
		if err := mfa.Disable(r.Context(), principal.UserID); err != nil {
			writeMFAStoreError(w, err, "failed to disable two-factor authentication")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func mfaRecoveryCodesHandler(mfa store.MFAStore, throttle store.LoginThrottleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := requireInteractiveSession(w, r)
		if !ok {
			return
		}
		if !verifyCodeForSensitiveMFAChange(w, r, mfa, throttle, principal) {
			return
		}
		codes, err := mfa.RegenerateRecoveryCodes(r.Context(), principal.UserID)
		if err != nil {
			writeMFAStoreError(w, err, "failed to regenerate recovery codes")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
	}
}

func verifyCodeForSensitiveMFAChange(w http.ResponseWriter, r *http.Request, mfa store.MFAStore, throttle store.LoginThrottleStore, principal AuthPrincipal) bool {
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	ip := clientIPFromRequest(r)
	if wait := loginRetryAfter(r.Context(), throttle, ip, principal.Email); wait > 0 {
		writeTooManyAttempts(w, wait)
		return false
	}
	valid, _, err := verifySecondFactor(r.Context(), mfa, principal.UserID, payload.Code)
	if err != nil {
		writeMFAStoreError(w, err, "failed to verify two-factor code")
		return false
	}
	if !valid {
		recordLoginFailure(r.Context(), throttle, ip, principal.Email)
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error:   "invalid_mfa_code",
			Message: "Invalid or already used code. Please try again.",
		})
		return false
	}
	return true
}

func adminResetMFAHandler(mfa store.MFAStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id <= 0 {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if err := mfa.Disable(r.Context(), id); err != nil {
			writeMFAStoreError(w, err, "failed to reset two-factor authentication")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
