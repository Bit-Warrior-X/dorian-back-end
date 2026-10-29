package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"vue-project-backend/internal/store"
)

type l7GuardAgentPayload struct {
	Token    string                `json:"token"`
	ServerID int64                 `json:"serverId"`
	L7Guard  store.L7GuardSettings `json:"l7guard"`
	Reset    bool                  `json:"reset,omitempty"`
}

func callL7UpdateL7Guard(ctx context.Context, servers store.ServerStore, serverID int64, settings store.L7GuardSettings, reset bool) error {
	return postL7ToServer(ctx, servers, serverID, "/API/L7/l7_update_l7guard", func(edgeID int64, server store.ServerView) ([]byte, error) {
		return json.Marshal(l7GuardAgentPayload{
			Token:    strings.TrimSpace(server.Token),
			ServerID: edgeID,
			L7Guard:  settings,
			Reset:    reset,
		})
	})
}

func serverL7GuardHandler(servers store.ServerStore, l7Guard store.L7GuardStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serverID, ok := parseIDWithSuffix(r.URL.Path, "/servers/", "/l7-guard")
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if _, err := servers.GetView(r.Context(), serverID); err != nil {
			if store.IsNotFound(err) {
				writeError(w, http.StatusNotFound, "server not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to load server")
			return
		}

		switch r.Method {
		case http.MethodGet:
			state, err := l7Guard.Get(r.Context(), serverID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load l7 guard settings")
				return
			}
			writeJSON(w, http.StatusOK, state)
		case http.MethodPut:
			raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			var envelope struct {
				Reset   bool            `json:"reset"`
				L7Guard json.RawMessage `json:"l7guard"`
			}
			if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&envelope); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}

			trimmed := bytes.TrimSpace(envelope.L7Guard)
			shouldReset := envelope.Reset || len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("{}"))

			var state store.L7GuardState
			if shouldReset {
				defaults := store.DefaultL7GuardSettings()
				if err := callL7UpdateL7Guard(r.Context(), servers, serverID, defaults, true); err != nil {
					writeL7GuardPushError(w, err)
					return
				}
				state, err = l7Guard.Reset(r.Context(), serverID)
			} else {
				normalized, normErr := store.DecodeL7GuardSettings(trimmed)
				if normErr != nil {
					writeError(w, http.StatusBadRequest, normErr.Error())
					return
				}
				if err := callL7UpdateL7Guard(r.Context(), servers, serverID, normalized, false); err != nil {
					writeL7GuardPushError(w, err)
					return
				}
				state, err = l7Guard.Upsert(r.Context(), serverID, normalized)
			}
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to save l7 guard settings")
				return
			}
			writeJSON(w, http.StatusOK, state)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func writeL7GuardPushError(w http.ResponseWriter, err error) {
	var statusErr *l7StatusError
	if errors.As(err, &statusErr) {
		msg := strings.TrimSpace(statusErr.Body)
		if msg == "" {
			msg = fmt.Sprintf("edge returned status %d", statusErr.Status)
		}
		writeError(w, http.StatusBadGateway, msg)
		return
	}
	writeError(w, http.StatusBadGateway, err.Error())
}
