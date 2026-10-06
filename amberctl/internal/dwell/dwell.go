// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package dwell

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

const idleThreshold = 5 * time.Minute

// ShouldDeferRebuild returns true when recent session activity suggests waiting (Stage-2 stub).
func ShouldDeferRebuild(svc string) (deferRebuild bool, reason string) {
	if os.Getenv("AMBER_FORCE_REBUILD") == "1" {
		return false, ""
	}
	evPath := filepath.Join(paths.EvidenceRoot(), "jsonl", svc, "events.jsonl")
	f, err := os.Open(evPath)
	if err != nil {
		return false, ""
	}
	defer f.Close()

	var lastTS string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if ts, ok := rec["ts"].(string); ok && ts != "" {
			lastTS = ts
		}
	}
	if lastTS == "" {
		return false, ""
	}
	t, err := time.Parse(time.RFC3339Nano, lastTS)
	if err != nil {
		return false, ""
	}
	age := time.Since(t)
	if age < idleThreshold {
		return true, "last activity " + age.Round(time.Second).String() + " ago (< 5m idle threshold)"
	}
	return false, ""
}
