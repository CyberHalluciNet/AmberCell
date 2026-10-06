// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

const schemaVersion = "review-item.v1"

// Item is an operator-facing uncertainty queue entry.
type Item struct {
	SchemaVersion string  `json:"schema_version"`
	ItemID        string  `json:"item_id"`
	DecisionID    string  `json:"decision_id"`
	Svc           string  `json:"svc,omitempty"`
	Confidence    string  `json:"confidence,omitempty"`
	Reason        string  `json:"reason_summary,omitempty"`
	Status        string  `json:"status"` // pending|approved|rejected
	EnqueuedAt    string  `json:"enqueued_at"`
	ResolvedAt    string  `json:"resolved_at,omitempty"`
	OperatorUID   int     `json:"operator_uid,omitempty"`
	Extra         map[string]any `json:"extra,omitempty"`
}

// PreferencePair logs human override for alignment (Stage-4).
type PreferencePair struct {
	SchemaVersion string `json:"schema_version"`
	Ts            string `json:"ts"`
	DecisionID    string `json:"decision_id"`
	Action        string `json:"action"` // approve|reject|modify
	OperatorUID   int    `json:"operator_uid"`
	Note          string `json:"note,omitempty"`
}

func queueDir() string {
	return filepath.Join(paths.EvidenceRoot(), "state", "review", "pending")
}

func preferencesDir() string {
	return filepath.Join(paths.EvidenceRoot(), "state", "preferences")
}

// Enqueue adds a pending review item (idempotent on decision_id filename).
func Enqueue(item Item) (string, error) {
	dir := queueDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	if item.SchemaVersion == "" {
		item.SchemaVersion = schemaVersion
	}
	if item.Status == "" {
		item.Status = "pending"
	}
	if item.EnqueuedAt == "" {
		item.EnqueuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	id := item.ItemID
	if id == "" {
		id = item.DecisionID
	}
	if id == "" {
		id = fmt.Sprintf("rev_%d", time.Now().UnixNano())
	}
	item.ItemID = id
	path := filepath.Join(dir, sanitize(id)+".json")
	raw, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		return "", err
	}
	return path, nil
}

// ListPending returns pending items optionally filtered by svc.
func ListPending(svc string) ([]Item, error) {
	dir := queueDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Item
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var it Item
		if json.Unmarshal(raw, &it) != nil {
			continue
		}
		if it.Status != "" && it.Status != "pending" {
			continue
		}
		if svc != "" && it.Svc != svc {
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

// Resolve moves item out of pending and logs preference pair.
func Resolve(decisionID, action, note string, operatorUID int) error {
	dir := queueDir()
	path := filepath.Join(dir, sanitize(decisionID)+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("review: no pending item for decision %q", decisionID)
	}
	var it Item
	if err := json.Unmarshal(raw, &it); err != nil {
		return err
	}
	it.Status = action
	it.ResolvedAt = time.Now().UTC().Format(time.RFC3339Nano)
	it.OperatorUID = operatorUID
	resolved := filepath.Join(paths.EvidenceRoot(), "state", "review", "resolved", sanitize(decisionID)+".json")
	if err := os.MkdirAll(filepath.Dir(resolved), 0o750); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(it, "", "  ")
	if err := os.WriteFile(resolved, out, 0o640); err != nil {
		return err
	}
	_ = os.Remove(path)
	return logPreference(PreferencePair{
		SchemaVersion: "preference-pair.v1",
		Ts:            time.Now().UTC().Format(time.RFC3339Nano),
		DecisionID:    decisionID,
		Action:        action,
		OperatorUID:   operatorUID,
		Note:          note,
	})
}

func logPreference(p PreferencePair) error {
	dir := preferencesDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s.json", sanitize(p.DecisionID), time.Now().UTC().Format("20060102T150405Z"))
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), raw, 0o640)
}

func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "item"
	}
	return string(out)
}
