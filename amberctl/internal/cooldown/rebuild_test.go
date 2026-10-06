// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cooldown

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRebuildCooldownMaxPerHour(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AMBER_EVIDENCE_ROOT", root)
	svc := "ftp"
	now := time.Now().UTC()
	h := &history{Timestamps: []time.Time{now.Add(-10 * time.Minute), now.Add(-8 * time.Minute), now.Add(-5 * time.Minute)}}
	if err := save(svc, h); err != nil {
		t.Fatal(err)
	}
	if err := CheckRebuild(svc); err == nil {
		t.Fatal("expected cooldown error after 3 rebuilds/hour")
	}
}

func TestRebuildCooldownMinGap(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AMBER_EVIDENCE_ROOT", root)
	svc := "smtp"
	now := time.Now().UTC()
	h := &history{Timestamps: []time.Time{now.Add(-2 * time.Minute)}}
	if err := os.MkdirAll(filepath.Join(root, "state"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := save(svc, h); err != nil {
		t.Fatal(err)
	}
	if err := CheckRebuild(svc); err == nil {
		t.Fatal("expected min-gap cooldown error")
	}
}
