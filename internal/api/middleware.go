package api

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/config"
)

type corsConfig struct {
	allowAll bool
	allowed  map[string]struct{}
}

func withCORS(cfg config.Config, next http.Handler) http.Handler {
	cors := corsConfig{
		allowAll: cfg.AllowAllCORS,
		allowed:  map[string]struct{}{},
	}

	if !cors.allowAll {
		for _, origin := range cfg.AllowedOrigins {
			cors.allowed[origin] = struct{}{}
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := origin != "" && cors.isAllowed(origin)
		if allowed {
			if cors.allowAll {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			requestedHeaders := r.Header.Get("Access-Control-Request-Headers")
			if requestedHeaders != "" {
				w.Header().Set("Access-Control-Allow-Headers", requestedHeaders)
				w.Header().Add("Vary", "Access-Control-Request-Headers")
			} else {
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		}

		if r.Method == http.MethodOptions {
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (c corsConfig) isAllowed(origin string) bool {
	if c.allowAll {
		return true
	}
	if origin == "" {
		return false
	}
	_, ok := c.allowed[origin]
	return ok
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

// Hijack forwards to the underlying ResponseWriter so WebSocket upgrades work
// through the logging wrapper (gorilla/websocket requires http.Hijacker).
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("responseWriter does not support hijacking")
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 0}
		next.ServeHTTP(rec, r)
		duration := time.Since(start).Truncate(time.Millisecond)
		path := r.URL.Path
		if strings.TrimSpace(path) == "" {
			path = "/"
		}
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		remote := strings.TrimSpace(r.RemoteAddr)
		if remote != "" {
			log.Printf("%s %s -> %d (%s) remote=%s", r.Method, path, status, duration, remote)
			return
		}
		log.Printf("%s %s -> %d (%s)", r.Method, path, status, duration)
	})
}
