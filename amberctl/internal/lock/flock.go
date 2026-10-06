// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package lock

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

// ErrLocked indicates another amberctl process holds the service lock.
type ErrLocked struct {
	Svc  string
	Path string
}

func (e *ErrLocked) Error() string {
	return fmt.Sprintf("service %q locked (%s); another lifecycle operation in progress", e.Svc, e.Path)
}

// WithExclusive runs fn while holding an exclusive flock on state/<svc>.lock.
// Returns *ErrLocked when the lock is already held (caller maps to exit 6).
func WithExclusive(svc string, fn func() error) error {
	if err := os.MkdirAll(filepath.Join(paths.EvidenceRoot(), "state"), 0o750); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	lockPath := filepath.Join(paths.EvidenceRoot(), "state", svc+".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return fmt.Errorf("open lock %s: %w", lockPath, err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if err == syscall.EWOULDBLOCK {
			return &ErrLocked{Svc: svc, Path: lockPath}
		}
		return fmt.Errorf("flock %s: %w", lockPath, err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	return fn()
}
