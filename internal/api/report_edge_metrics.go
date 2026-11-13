package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"vue-project-backend/internal/store"
	"vue-project-backend/internal/worker"
)

type edgeMetricsReportPayload struct {
	Token           string                 `json:"token"`
	Command         string                 `json:"command"`
	ReportedAt      flexibleInt64          `json:"reported_at"`
	IntervalSeconds flexibleInt64          `json:"interval_seconds"`
	LicenseType     string                 `json:"license_type"`
	AllowsL4        *bool                  `json:"allows_l4"`
	AllowsL7        *bool                  `json:"allows_l7"`
	ItemCount       flexibleInt64          `json:"item_count"`
	Source          string                 `json:"source"`
	Endpoint        string                 `json:"endpoint"`
	EndpointAliases []string               `json:"endpoint_aliases"`
	Timestamp       flexibleInt64          `json:"timestamp"`
	Payload         json.RawMessage        `json:"payload"`
	Items           []worker.EdgeMetricsItem `json:"items"`
}

type edgeMetricsReportResult struct {
	Status     string `json:"status"`
	ServerID   int64  `json:"serverId"`
	Accepted   int    `json:"accepted"`
	Skipped    int    `json:"skipped"`
	Failed     int    `json:"failed"`
	ReportedAt int64  `json:"reportedAt,omitempty"`
}

func reportEdgeMetricsHandler(servers store.ServerStore, dbConn *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if dbConn == nil {
			writeError(w, http.StatusInternalServerError, "metrics store unavailable")
			return
		}

		var payload edgeMetricsReportPayload
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&payload); err != nil {
			log.Printf("[api] report_edge_metrics invalid JSON: %v", err)
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		payload.Token = strings.TrimSpace(payload.Token)
		if payload.Token == "" {
			payload.Token = extractBearerOrAPIKey(r)
		}
		payload.Command = strings.TrimSpace(payload.Command)
		if payload.Token == "" {
			writeError(w, http.StatusForbidden, "missing token")
			return
		}
		if payload.Command != "" && !strings.EqualFold(payload.Command, "report_edge_metrics") {
			writeError(w, http.StatusBadRequest, "unsupported command")
			return
		}

		server, err := servers.GetByToken(r.Context(), payload.Token)
		if err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusForbidden, "invalid token")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to validate token")
			return
		}

		items := payload.Items
		if len(items) == 0 && (strings.TrimSpace(payload.Endpoint) != "" || len(payload.Payload) > 0) {
			items = []worker.EdgeMetricsItem{{
				Source:          payload.Source,
				Endpoint:        payload.Endpoint,
				EndpointAliases: payload.EndpointAliases,
				Timestamp:       payload.Timestamp.Int64(),
				IntervalSeconds: payload.IntervalSeconds.Int64(),
				Payload:         payload.Payload,
			}}
		}
		if len(items) == 0 {
			writeError(w, http.StatusBadRequest, "missing items")
			return
		}

		allowsL4 := true
		allowsL7 := true
		if payload.AllowsL4 != nil {
			allowsL4 = *payload.AllowsL4
		}
		if payload.AllowsL7 != nil {
			allowsL7 = *payload.AllowsL7
		}

		result := edgeMetricsReportResult{
			Status:     "success",
			ServerID:   server.ID,
			ReportedAt: payload.ReportedAt.Int64(),
		}
		for _, item := range items {
			source := strings.ToLower(strings.TrimSpace(item.Source))
			endpoint := strings.ToLower(strings.TrimSpace(item.Endpoint))
			if source == "sparta" || endpoint == "l4_traffic_stats" || endpoint == "l4_attack_stats" {
				if !allowsL4 {
					result.Skipped++
					continue
				}
			} else if source == "athens" || source == "" {
				if !allowsL7 {
					result.Skipped++
					continue
				}
			}
			if err := worker.IngestEdgeMetricsItem(r.Context(), dbConn, server.ID, item); err != nil {
				result.Failed++
				log.Printf("[api] report_edge_metrics server=%d endpoint=%s ts=%d: %v",
					server.ID, item.Endpoint, item.Timestamp, err)
				continue
			}
			result.Accepted++
		}

		writeJSON(w, http.StatusOK, result)
	}
}
