// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

// flushEvidenceSegment closes active JSONL segments via collector vault helper (host-side).
func flushEvidenceSegment(svc string) error {
	root, err := paths.FindComposeRoot()
	if err != nil {
		return err
	}
	script := filepath.Join(root, "collectors", "base", "ambercell", "vault_flush.py")
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("vault flush script missing: %w", err)
	}
	cmd := exec.Command("python3", script, "--svc", svc)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"AMBER_EVIDENCE_ROOT="+paths.EvidenceRoot(),
		"PYTHONPATH="+filepath.Join(root, "collectors", "base"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	if len(out) > 0 {
		fmt.Fprintf(os.Stderr, "amberctl: %s", out)
	}
	return nil
}
