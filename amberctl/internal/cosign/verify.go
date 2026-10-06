// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cosign

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// VerifyDigest checks image digest signatures when enforcement is enabled.
// AMBER_COSIGN_ENFORCE=1 requires cosign verify; missing cosign binary fails closed.
// AMBER_COSIGN_ENFORCE unset or 0 logs stub OK (lab default).
func VerifyDigest(imageRef, digest string) error {
	enforce := strings.TrimSpace(os.Getenv("AMBER_COSIGN_ENFORCE"))
	if enforce != "1" && !strings.EqualFold(enforce, "true") {
		fmt.Fprintf(os.Stderr, "amberctl: cosign verify stub OK (set AMBER_COSIGN_ENFORCE=1 to enforce) digest=%s\n", digest)
		return nil
	}
	if _, err := exec.LookPath("cosign"); err != nil {
		return fmt.Errorf("cosign enforce enabled but cosign not in PATH")
	}
	ref := imageRef
	if digest != "" && !strings.Contains(ref, "@") {
		ref = ref + "@" + digest
	}
	cmd := exec.Command("cosign", "verify", ref)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign verify failed for %s: %w", ref, err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: cosign verify OK %s\n", ref)
	return nil
}
