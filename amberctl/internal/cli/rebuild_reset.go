// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/canary"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/conntrack"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/cooldown"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/cosign"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/dwell"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/lock"
)

func supportedCell(svc string) bool {
	_, ok := compose.Cells[svc]
	return ok
}

func runRebuild(args []string) error {
	if len(args) != 1 || !supportedCell(args[0]) {
		return fmt.Errorf("usage: amberctl rebuild %s", cellUsage)
	}
	svc := args[0]
	if deferRebuild, reason := dwell.ShouldDeferRebuild(svc); deferRebuild {
		return exitErr(4,
			"amberctl: dwell-time deferred rebuild for %s (%s); set AMBER_FORCE_REBUILD=1 to override",
			svc, reason,
		)
	}
	return withLifecycleLock(svc, "rebuild", func() error {
		if err := cooldown.CheckRebuild(svc); err != nil {
			return exitErr(5, "%v", err)
		}
		if err := rebuildCell(svc); err != nil {
			return err
		}
		if err := cooldown.RecordRebuild(svc); err != nil {
			fmt.Fprintf(os.Stderr, "amberctl: rebuild: record cooldown: %v\n", err)
		}
		return nil
	})
}

func runReset(args []string) error {
	if len(args) != 1 || !supportedCell(args[0]) {
		return fmt.Errorf("usage: amberctl reset %s", cellUsage)
	}
	svc := args[0]
	return withLifecycleLock(svc, "reset", func() error {
		fmt.Fprintf(os.Stderr, "amberctl: reset %s (recycle containers + regenerate canaries/seeds)\n", svc)
		return rebuildCell(svc)
	})
}

func withLifecycleLock(svc, action string, fn func() error) error {
	compose.LogInvokerUID(action + " " + svc)
	err := lock.WithExclusive(svc, fn)
	if err == nil {
		return nil
	}
	var locked *lock.ErrLocked
	if errors.As(err, &locked) {
		return exitErr(6, "%s %s: %v", action, svc, err)
	}
	return err
}

func rebuildCell(svc string) error {
	cellIP := compose.CellIP(svc)
	// Order: lock held → stop hi → wait → conntrack flush → stop collector → canaries → up.
	if err := compose.StopHI(svc); err != nil {
		return fmt.Errorf("rebuild: stop hi: %w", err)
	}
	time.Sleep(5 * time.Second)
	if err := flushEvidenceSegment(svc); err != nil {
		fmt.Fprintf(os.Stderr, "amberctl: evidence flush: %v (continuing)\n", err)
	}
	if err := conntrack.FlushCell(cellIP); err != nil {
		return fmt.Errorf("rebuild: conntrack: %w", err)
	}
	if err := compose.StopCollector(svc); err != nil {
		return fmt.Errorf("rebuild: stop collector: %w", err)
	}
	spec, ok := compose.Cells[svc]
	if ok {
		prov := os.Getenv(spec.ProviderEnv)
		if prov == "" {
			prov = spec.DefaultProv
		}
		hiRef := fmt.Sprintf(spec.HiImageFmt, prov)
		if err := cosign.VerifyDigest(hiRef, os.Getenv(spec.HiDigestEnv)); err != nil {
			return fmt.Errorf("rebuild: cosign: %w", err)
		}
		if err := cosign.VerifyDigest(spec.CollectorImage, os.Getenv("AMBER_IMAGE_DIGEST")); err != nil {
			return fmt.Errorf("rebuild: cosign: %w", err)
		}
	}
	if _, err := canary.Generate(svc); err != nil {
		fmt.Fprintf(os.Stderr, "amberctl: canary generate: %v (continuing)\n", err)
	}
	if err := compose.UpCell(svc); err != nil {
		return fmt.Errorf("rebuild: up: %w", err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: rebuild %s complete\n", svc)
	return nil
}
