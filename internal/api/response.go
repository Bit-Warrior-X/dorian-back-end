package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"vue-project-backend/internal/applog"
)

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeErrorResponse(w, status, errorResponse{
		Error:   http.StatusText(status),
		Message: message,
	})
}

func writeErrorResponse(w http.ResponseWriter, status int, payload errorResponse) {
	if strings.TrimSpace(payload.Error) == "" {
		payload.Error = http.StatusText(status)
	}
	if strings.TrimSpace(payload.Message) == "" {
		payload.Message = payload.Error
	}
	level := "warn"
	if status >= 500 {
		level = "error"
	}
	applog.Event(level, "api", "http_error_response", map[string]any{
		"status":       status,
		"message":      oneLineLogPreview(payload.Message, 240),
		"script_error": oneLineLogPreview(payload.ScriptError, 240),
		"req_id":       payload.ReqID,
		"op":           payload.Op,
	})
	// Keep std log bridge for older greps during transition.
	if status >= 500 {
		log.Printf("[api] error response status=%d message=%s", status, oneLineLogPreview(payload.Message, 240))
	}
	writeJSON(w, status, payload)
}

func writeHTTPAPIError(w http.ResponseWriter, err *httpAPIErr) {
	payload := err.detail
	if strings.TrimSpace(payload.Message) == "" {
		payload.Message = err.message
	}
	if strings.TrimSpace(payload.Error) == "" {
		payload.Error = http.StatusText(err.status)
	}
	writeErrorResponse(w, err.status, payload)
}
