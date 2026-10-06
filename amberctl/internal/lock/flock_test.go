// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package lock

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

func TestConcurrentFlockSecondFails(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AMBER_EVIDENCE_ROOT", root)
	_ = paths.EvidenceRoot()

	var wg sync.WaitGroup
	wg.Add(1)
	hold := make(chan struct{})
	go func() {
		defer wg.Done()
		_ = WithExclusive("ftp", func() error {
			close(hold)
			time.Sleep(200 * time.Millisecond)
			return nil
		})
	}()
	<-hold
	err := WithExclusive("ftp", func() error { return nil })
	if err == nil {
		t.Fatal("expected second flock to fail")
	}
	var locked *ErrLocked
	if !asErrLocked(err, &locked) {
		t.Fatalf("expected *ErrLocked, got %T %v", err, err)
	}
	wg.Wait()
}

func asErrLocked(err error, target **ErrLocked) bool {
	if err == nil {
		return false
	}
	if l, ok := err.(*ErrLocked); ok {
		*target = l
		return true
	}
	return false
}

func TestLockFileCreated(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AMBER_EVIDENCE_ROOT", root)
	_ = WithExclusive("telnet", func() error { return nil })
	lockPath := filepath.Join(root, "state", "telnet.lock")
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file: %v", err)
	}
}
