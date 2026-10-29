package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/applog"
	"vue-project-backend/internal/store"
)

type reportL7AttackPayload struct {
	Token      string                 `json:"token"`
	Command    string                 `json:"command"`
	Data       string                 `json:"data"`
	ReqID      flexString             `json:"req_id"`
	Time       string                 `json:"time"`
	ReportedAt int64                  `json:"reported_at"`
	Attack     store.L7AttackIncident `json:"attack"`
}

func reportL7AttackHandler(
	servers store.ServerStore,
	securityEvents store.SecurityEventStore,
	l7Attacks store.L7AttackStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		// Angelos may concatenate attack_start + attack_stop (same as L4 report_attack)
		// when catching up after a failed delivery. Accept one object, many objects, or an array.
		payloads, err := decodeL7AttackPayloads(body)
		if err != nil {
			applog.Warnf("api", "report_l7_attack_bad_json", map[string]any{
				"bytes": len(body),
				"error": err.Error(),
			})
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		var (
			carriedToken string
			lastRecord   store.L7AttackRecord
			lastData     string
			lastReqID    string
			lastServerID int64
		)
		for _, payload := range payloads {
			token := strings.TrimSpace(payload.Token)
			if token == "" {
				if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
					token = strings.TrimSpace(auth[7:])
				}
			}
			if token == "" {
				token = carriedToken
			}
			if token == "" {
				writeError(w, http.StatusForbidden, "missing token")
				return
			}
			carriedToken = token

			command := strings.ToLower(strings.TrimSpace(payload.Command))
			if command == "" {
				command = "report_l7_attack"
			}
			if command != "report_l7_attack" {
				writeError(w, http.StatusBadRequest, "unsupported command")
				return
			}
			data := strings.ToLower(strings.TrimSpace(payload.Data))
			switch data {
			case "attack_start", "attack_update", "attack_stop":
			default:
				writeError(w, http.StatusBadRequest, "unsupported data")
				return
			}

			reqID := strings.TrimSpace(payload.ReqID.String())
			if reqID == "" {
				reqID = strings.TrimSpace(payload.Attack.ID)
			}
			if reqID == "" {
				writeError(w, http.StatusBadRequest, "missing req_id")
				return
			}
			payload.Attack.ID = reqID

			server, err := servers.GetByToken(r.Context(), token)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusForbidden, "invalid token")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to validate token")
				return
			}

			occurredAt, err := parseReportEventTime(payload.Time)
			if err != nil || occurredAt.IsZero() {
				if payload.ReportedAt > 0 {
					occurredAt = time.Unix(payload.ReportedAt, 0).UTC()
				} else if payload.Attack.UpdatedAt > 0 {
					occurredAt = time.Unix(payload.Attack.UpdatedAt, 0).UTC()
				} else if payload.Attack.StartedAt > 0 {
					occurredAt = time.Unix(payload.Attack.StartedAt, 0).UTC()
				} else {
					occurredAt = time.Now().UTC()
				}
			}

			record, err := l7Attacks.Upsert(r.Context(), server.ID, data, payload.Attack)
			if err != nil {
				if store.IsNotFound(err) {
					writeError(w, http.StatusForbidden, "invalid token")
					return
				}
				writeError(w, http.StatusInternalServerError, "failed to store l7 attack")
				return
			}

			if err := ensureL7AttackSecurityEvents(r, securityEvents, server.ID, data, reqID, occurredAt, record); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to store security event")
				return
			}

			lastRecord = record
			lastData = data
			lastReqID = reqID
			lastServerID = server.ID
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "success",
			"req_id":   lastReqID,
			"data":     lastData,
			"attack":   lastRecord.Incident,
			"serverId": lastServerID,
			"count":    len(payloads),
		})
	}
}

func decodeL7AttackPayloads(body []byte) ([]reportL7AttackPayload, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	if body[0] == '[' {
		var payloads []reportL7AttackPayload
		if err := json.Unmarshal(body, &payloads); err != nil {
			return nil, err
		}
		if len(payloads) == 0 {
			return nil, errors.New("empty body")
		}
		return payloads, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	payloads := make([]reportL7AttackPayload, 0, 2)
	for {
		var payload reportL7AttackPayload
		if err := dec.Decode(&payload); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if len(payloads) == 0 {
				return nil, err
			}
			break
		}
		payloads = append(payloads, payload)
	}
	if len(payloads) == 0 {
		return nil, errors.New("empty body")
	}
	return payloads, nil
}

// ensureL7AttackSecurityEvents writes alert rows for start/stop. Updates are silent
// unless this is the first panel sighting of the incident (missed/failed start),
// in which case a synthetic attack_start is inserted so the UI can open promptly.
// Stop without a prior start also backfills start (Angelos catch-up path).
func ensureL7AttackSecurityEvents(
	r *http.Request,
	securityEvents store.SecurityEventStore,
	serverID int64,
	data, reqID string,
	occurredAt time.Time,
	record store.L7AttackRecord,
) error {
	hasStart, hasStop := false, false
	if period, err := securityEvents.GetPeriod(r.Context(), reqID); err == nil {
		for _, event := range period.Events {
			switch strings.ToLower(strings.TrimSpace(event.Data)) {
			case "attack_start":
				hasStart = true
			case "attack_stop":
				hasStop = true
			}
		}
	} else if !store.IsNotFound(err) {
		return err
	}

	write := func(eventData string, at time.Time) error {
		title, description := buildL7AttackSecurityEvent(eventData, record)
		report := store.SecurityEventReport{
			Command:    "report_l7_attack",
			AttackType: strings.Join(record.Vectors, "+"),
			Data:       eventData,
			ReqID:      reqID,
			TTL:        strconv.Itoa(record.UniqueIPs),
		}
		return securityEvents.Create(r.Context(), serverID, title, description, at, report)
	}

	needStart := !hasStart && (data == "attack_start" || data == "attack_update" || data == "attack_stop")
	if needStart {
		startAt := occurredAt
		if data != "attack_start" && record.StartedAt.Unix() > 0 {
			startAt = record.StartedAt.UTC()
		}
		if err := write("attack_start", startAt); err != nil {
			return err
		}
		hasStart = true
	}

	if data == "attack_stop" && !hasStop {
		return write("attack_stop", occurredAt)
	}
	return nil
}

func buildL7AttackSecurityEvent(data string, record store.L7AttackRecord) (string, string) {
	labels := make([]string, 0, len(record.Vectors))
	for _, raw := range record.Vectors {
		if label := store.L7VectorLabel(raw); label != "" {
			labels = append(labels, label)
		}
	}
	vectorText := "L7 attack"
	switch len(labels) {
	case 1:
		vectorText = labels[0]
	case 2:
		vectorText = labels[0] + " + " + labels[1]
	case 3, 4:
		vectorText = strings.Join(labels[:len(labels)-1], ", ") + " + " + labels[len(labels)-1]
	}
	title := vectorText + " attack"
	ratio := record.Incident.BlockedRatio
	if ratio <= 0 && record.Incident.Totals != nil && record.TotalRequests > 0 {
		switch raw := record.Incident.Totals["blocked"].(type) {
		case float64:
			if raw > 0 {
				ratio = raw / float64(record.TotalRequests)
			}
		case int:
			if raw > 0 {
				ratio = float64(raw) / float64(record.TotalRequests)
			}
		case int64:
			if raw > 0 {
				ratio = float64(raw) / float64(record.TotalRequests)
			}
		}
	}
	ratioText := ""
	if ratio > 0 {
		ratioText = fmt.Sprintf(" · %.0f%% blocked", ratio*100)
	}
	if data == "attack_stop" {
		return title, fmt.Sprintf("L7 attack has stopped · %d unique IPs · peak %d rps%s", record.UniqueIPs, record.PeakRPS, ratioText)
	}
	return title, fmt.Sprintf("L7 attack has started · %d unique IPs · peak %d rps%s", record.UniqueIPs, record.PeakRPS, ratioText)
}
