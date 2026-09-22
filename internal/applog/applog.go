package applog

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Install configures the standard library logger to emit one JSON object per line.
// Existing log.Printf call sites then produce scannable structured logs.
func Install(component string) {
	if strings.TrimSpace(component) == "" {
		component = "api"
	}
	defaultComponent = component
	log.SetFlags(0)
	log.SetOutput(&stdWriter{component: component})
}

var (
	defaultComponent = "api"
	mu               sync.Mutex
)

type stdWriter struct {
	component string
}

func (w *stdWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(bytes.TrimRight(p, "\r\n")))
	if msg == "" {
		return len(p), nil
	}
	// Already JSON from applog.Event / request middleware.
	if strings.HasPrefix(msg, "{") && strings.HasSuffix(msg, "}") {
		mu.Lock()
		_, _ = os.Stderr.Write(append([]byte(msg), '\n'))
		mu.Unlock()
		return len(p), nil
	}
	level := "info"
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, " error"), strings.HasPrefix(lower, "error"), strings.Contains(lower, "failed"):
		level = "error"
	case strings.Contains(lower, "warn"), strings.Contains(lower, "warning"):
		level = "warn"
	}
	Event(level, w.component, "log", map[string]any{"msg": msg})
	return len(p), nil
}

// Event writes one structured JSON log line to stderr.
func Event(level, component, event string, fields map[string]any) {
	if strings.TrimSpace(component) == "" {
		component = defaultComponent
	}
	if strings.TrimSpace(level) == "" {
		level = "info"
	}
	entry := map[string]any{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level,
		"component": component,
		"event":     event,
	}
	for k, v := range fields {
		if v == nil {
			continue
		}
		entry[k] = v
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		mu.Lock()
		_, _ = io.WriteString(os.Stderr, `{"level":"error","component":"applog","event":"marshal_failed","msg":"`+err.Error()+`"}`+"\n")
		mu.Unlock()
		return
	}
	mu.Lock()
	_, _ = os.Stderr.Write(append(raw, '\n'))
	mu.Unlock()
}

func Infof(component, event string, fields map[string]any) {
	Event("info", component, event, fields)
}

func Warnf(component, event string, fields map[string]any) {
	Event("warn", component, event, fields)
}

func Errorf(component, event string, fields map[string]any) {
	Event("error", component, event, fields)
}
