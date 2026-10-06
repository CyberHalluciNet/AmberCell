// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/canary"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

func runInit(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("init: unexpected arguments %v", args)
	}
	compose.LogInvokerUID("init")

	root := paths.EvidenceRoot()
	const dirMode = 0o750
	for _, sub := range paths.InitSubdirs {
		p := filepath.Join(root, sub)
		if err := os.MkdirAll(p, dirMode); err != nil {
			return fmt.Errorf("init: mkdir %s: %w", p, err)
		}
	}
	for _, extra := range []string{
		"run", "state/canaries", "state/review/pending", "state/review/resolved",
		"state/preferences", "alerts/failed", "vault",
	} {
		if err := os.MkdirAll(filepath.Join(root, extra), dirMode); err != nil {
			return fmt.Errorf("init: mkdir %s: %w", extra, err)
		}
	}
	marker := filepath.Join(root, paths.InitMarker)
	if err := os.WriteFile(marker, []byte("stage=4\n"), 0o640); err != nil {
		return fmt.Errorf("init: write marker: %w", err)
	}
	notes := filepath.Join(root, "state", "permissions.notes")
	_ = os.WriteFile(notes, []byte(
		"Production: chown -R root:amber "+root+" && chmod 0750 "+root+"\n"+
			"Group amber for operators; amber-drop only for deaddrop/.\n"+
			"Canaries use prefix "+canary.Prefix+"\n",
	), 0o640)

	for _, svc := range []string{"ftp", "telnet"} {
		if _, err := canary.Generate(svc); err != nil {
			fmt.Fprintf(os.Stderr, "amberctl: init canary %s: %v\n", svc, err)
		}
	}

	fmt.Printf("initialized evidence tree under %s (mode 0750; prod owner root:amber)\n", root)
	return nil
}
