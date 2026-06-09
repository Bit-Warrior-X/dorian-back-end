package api

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"vue-project-backend/internal/store"
)

const (
	//defaultAccessLogPath  = "/var/log/nginx/access.log"
	defaultAccessLogPath  = "/tmp/on"
	defaultAccessLogLines = 200
	maxAccessLogLines     = 2000
	accessLogStreamMaxDur = 30 * time.Minute
	maxStreamsPerServer   = 3 // allow reconnects and multiple tabs
)

var (
	accessLogStreamMu     sync.Mutex
	accessLogStreamActive = make(map[int64]int)
)

type accessLogMessage struct {
	Line string `json:"line"`
}

func streamAccessLog(w http.ResponseWriter, r *http.Request, servers store.ServerStore, serverID int64) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool {
			return true
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[api] GET /servers/%d/access-log/stream: websocket upgrade failed: %v", serverID, err)
		return
	}
	defer conn.Close()

	accessLogStreamMu.Lock()
	if accessLogStreamActive[serverID] >= maxStreamsPerServer {
		accessLogStreamMu.Unlock()
		_ = conn.WriteJSON(errorResponse{Error: "busy", Message: "access log stream already active for this server"})
		return
	}
	accessLogStreamActive[serverID]++
	accessLogStreamMu.Unlock()
	defer func() {
		accessLogStreamMu.Lock()
		if accessLogStreamActive[serverID] > 0 {
			accessLogStreamActive[serverID]--
		}
		if accessLogStreamActive[serverID] == 0 {
			delete(accessLogStreamActive, serverID)
		}
		accessLogStreamMu.Unlock()
	}()

	view, err := servers.GetView(r.Context(), serverID)
	if err != nil {
		if store.IsNotFound(err) {
			_ = conn.WriteJSON(errorResponse{Error: "not found", Message: "server not found"})
			return
		}
		_ = conn.WriteJSON(errorResponse{Error: "internal error", Message: "failed to load server"})
		return
	}

	ip := strings.TrimSpace(view.IP)
	user := strings.TrimSpace(view.SSHUser)
	password := strings.TrimSpace(view.SSHPassword)
	port := strings.TrimSpace(view.SSHPort)
	if port == "" {
		port = "22"
	}
	if ip == "" || user == "" || password == "" {
		_ = conn.WriteJSON(errorResponse{Error: "bad request", Message: "server SSH credentials are missing"})
		return
	}

	lines := parseLogLines(r.URL.Query().Get("lines"))
	logPath := sanitizeLogPath(r.URL.Query().Get("path"))
	if logPath == "" {
		logPath = defaultAccessLogPath
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(ip, port), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	})
	if err != nil {
		_ = conn.WriteJSON(errorResponse{Error: "connection failed", Message: "failed to connect to server via SSH"})
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		_ = conn.WriteJSON(errorResponse{Error: "connection failed", Message: "failed to create SSH session"})
		return
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = conn.WriteJSON(errorResponse{Error: "stream error", Message: "failed to read access log"})
		return
	}

	cmd := fmt.Sprintf("tail -n %d -F %s", lines, logPath)
	if err := session.Start(cmd); err != nil {
		_ = conn.WriteJSON(errorResponse{Error: "stream error", Message: "failed to start log stream"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), accessLogStreamMaxDur)
	defer cancel()
	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			_ = session.Signal(ssh.SIGTERM)
			_ = session.Close()
			_ = client.Close()
		case <-done:
		}
	}()

	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				cancel()
				return
			}
		}
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineCh := make(chan string, 64)
	go func() {
		defer close(lineCh)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			line := scanner.Text()
			if line != "" {
				select {
				case lineCh <- line:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-lineCh:
			if !ok {
				return
			}
			if err := conn.WriteJSON(accessLogMessage{Line: line}); err != nil {
				return
			}
		}
	}
}

func parseLogLines(raw string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || parsed <= 0 {
		return defaultAccessLogLines
	}
	if parsed > maxAccessLogLines {
		return maxAccessLogLines
	}
	return parsed
}

func sanitizeLogPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	for _, r := range trimmed {
		if r == '/' || r == '.' || r == '-' || r == '_' {
			continue
		}
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		return ""
	}
	return trimmed
}
