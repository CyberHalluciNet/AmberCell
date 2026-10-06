// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cooldown

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

const (
	minGap      = 15 * time.Minute
	maxPerHour  = 3
	historyFile = "rebuild_history.json"
)

type history struct {
	Timestamps []time.Time `json:"timestamps"`
}

// CheckRebuild returns an error if cooldown limits would be exceeded by another rebuild now.
func CheckRebuild(svc string) error {
	h, err := load(svc)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	cutoff := now.Add(-time.Hour)
	var recent []time.Time
	for _, t := range h.Timestamps {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= maxPerHour {
		return fmt.Errorf(
			"rebuild cooldown: %d rebuilds in the last hour for %q (max %d); operator approval required (Stage-1 stub)",
			len(recent), svc, maxPerHour,
		)
	}
	if len(recent) > 0 {
		last := recent[len(recent)-1]
		if now.Sub(last) < minGap {
			wait := minGap - now.Sub(last)
			return fmt.Errorf(
				"rebuild cooldown: last rebuild %s ago for %q; wait %s (15m minimum gap, Stage-1 stub)",
				now.Sub(last).Truncate(time.Second), svc, wait.Truncate(time.Second),
			)
		}
	}
	return nil
}

// RecordRebuild appends a rebuild timestamp after a successful rebuild.
func RecordRebuild(svc string) error {
	h, err := load(svc)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	cutoff := now.Add(-24 * time.Hour)
	var kept []time.Time
	for _, t := range h.Timestamps {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	h.Timestamps = kept
	return save(svc, h)
}

func historyPath(svc string) string {
	return filepath.Join(paths.EvidenceRoot(), "state", svc+"."+historyFile)
}

func load(svc string) (*history, error) {
	path := historyPath(svc)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &history{}, nil
		}
		return nil, fmt.Errorf("read rebuild history: %w", err)
	}
	var h history
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("parse rebuild history: %w", err)
	}
	return &h, nil
}

func save(svc string, h *history) error {
	if err := os.MkdirAll(filepath.Join(paths.EvidenceRoot(), "state"), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(historyPath(svc), data, 0o640)
}
