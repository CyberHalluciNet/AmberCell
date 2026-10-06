// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

const (
	maxFailsBeforeDegrade = 3
	perRequestTimeout     = 2 * time.Second
	queueCapacity         = 256
)

// Alert is the JSON envelope sent to SIEM/Slack/PagerDuty endpoints.
type Alert struct {
	SchemaVersion string         `json:"schema_version"`
	AlertID       string         `json:"alert_id"`
	Ts            string         `json:"ts"`
	Kind          string         `json:"kind"`
	Svc           string         `json:"svc,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	CellID        string         `json:"cell_id,omitempty"`
	DecisionID    string         `json:"decision_id,omitempty"`
	Summary       string         `json:"summary"`
	Extra         map[string]any `json:"extra,omitempty"`
}

// Router delivers alerts asynchronously with a circuit breaker; never blocks callers.
type Router struct {
	url   string
	token string

	mu       sync.Mutex
	failures int
	degraded bool

	ch     chan Alert
	once   sync.Once
	client *http.Client
}

var defaultRouter *Router

// Default returns the process-wide webhook router (lazy worker).
func Default() *Router {
	if defaultRouter == nil {
		defaultRouter = &Router{
			url:   os.Getenv("AMBER_WEBHOOK_URL"),
			token: os.Getenv("AMBER_WEBHOOK_TOKEN"),
			ch:    make(chan Alert, queueCapacity),
			client: &http.Client{
				Timeout: perRequestTimeout,
			},
		}
	}
	return defaultRouter
}

func (r *Router) refreshFromEnv() {
	if u := os.Getenv("AMBER_WEBHOOK_URL"); u != "" {
		r.url = u
	}
	if t := os.Getenv("AMBER_WEBHOOK_TOKEN"); t != "" {
		r.token = t
	}
}

// Enqueue schedules alert delivery; returns immediately (drops if queue full).
func (r *Router) Enqueue(a Alert) {
	r.refreshFromEnv()
	if r.url == "" {
		return
	}
	r.once.Do(r.startWorker)
	r.normalize(&a)
	select {
	case r.ch <- a:
	default:
		_ = r.spill(a, "queue_full")
	}
}

// EnqueueAndTryDeliver is for one-shot CLIs: queue then attempt delivery before process exit.
func (r *Router) EnqueueAndTryDeliver(a Alert) {
	r.refreshFromEnv()
	if r.url == "" {
		return
	}
	r.normalize(&a)
	_ = r.persistPending(a)
	r.deliverOne(a)
}

func (r *Router) normalize(a *Alert) {
	if a.SchemaVersion == "" {
		a.SchemaVersion = "alert.v1"
	}
	if a.Ts == "" {
		a.Ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
}

func (r *Router) persistPending(a Alert) error {
	root := paths.EvidenceRoot()
	dir := filepath.Join(root, "alerts", "pending")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s.json", sanitize(a.AlertID), time.Now().UTC().Format("20060102T150405Z"))
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), raw, 0o640)
}

func (r *Router) startWorker() {
	go func() {
		for a := range r.ch {
			r.deliverOne(a)
		}
	}()
}

func (r *Router) deliverOne(a Alert) {
	if r.client == nil {
		r.client = &http.Client{Timeout: perRequestTimeout}
	}
	if r.degraded {
		_ = r.spill(a, "circuit_open")
		return
	}
	body, err := json.Marshal(a)
	if err != nil {
		_ = r.spill(a, "marshal_error")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), perRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		r.recordFailure(a, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		r.recordFailure(a, err)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		r.mu.Lock()
		r.failures = 0
		r.degraded = false
		r.mu.Unlock()
		return
	}
	r.recordFailure(a, fmt.Errorf("HTTP %d", resp.StatusCode))
}

func (r *Router) recordFailure(a Alert, err error) {
	r.mu.Lock()
	r.failures++
	if r.failures >= maxFailsBeforeDegrade {
		r.degraded = true
	}
	r.mu.Unlock()
	_ = r.spill(a, err.Error())
}

// Degraded reports whether the breaker is open.
func (r *Router) Degraded() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.degraded
}

func (r *Router) spill(a Alert, reason string) error {
	root := paths.EvidenceRoot()
	dir := filepath.Join(root, "alerts", "failed")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s.json", sanitize(a.AlertID), time.Now().UTC().Format("20060102T150405.000000000Z"))
	path := filepath.Join(dir, name)
	payload := map[string]any{
		"schema_version": "alert-spill.v1",
		"reason":         reason,
		"webhook_url_set": r.url != "",
		"alert":          a,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o640)
}

func sanitize(s string) string {
	if s == "" {
		return "alert"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}
