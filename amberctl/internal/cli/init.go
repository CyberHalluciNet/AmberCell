// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/canary"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/wizard"
)

func runInit(args []string) error {
	yes, forceWizard, cells, err := parseInitArgs(args)
	if err != nil {
		return err
	}
	if forceWizard && wizard.NonInteractive(yes) {
		return fmt.Errorf("init: --wizard conflicts with --yes / AMBER_INIT_NONINTERACTIVE")
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

	runWizard := false
	switch {
	case wizard.NonInteractive(yes):
		runWizard = false
	case forceWizard:
		runWizard = true
	case wizard.IsTTY():
		runWizard = true
	default:
		runWizard = false
	}

	if !runWizard {
		return nil
	}

	composeRoot, err := paths.FindComposeRoot()
	if err != nil {
		return fmt.Errorf("init wizard: %w", err)
	}
	if forceWizard && os.Stdin == nil {
		return fmt.Errorf("init: --wizard requires stdin")
	}

	return wizard.Run(wizard.Options{
		Root:       composeRoot,
		Cells:      cells,
		ForceStdin: forceWizard,
	})
}

func parseInitArgs(args []string) (yes, forceWizard bool, cells []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--yes" || a == "-y":
			yes = true
		case a == "--wizard":
			forceWizard = true
		case a == "--cells":
			if i+1 >= len(args) {
				return false, false, nil, fmt.Errorf("init: --cells requires a value (e.g. ftp,smtp)")
			}
			i++
			cells, err = splitCells(args[i])
			if err != nil {
				return false, false, nil, err
			}
		case strings.HasPrefix(a, "--cells="):
			cells, err = splitCells(strings.TrimPrefix(a, "--cells="))
			if err != nil {
				return false, false, nil, err
			}
		case a == "-h" || a == "--help":
			return false, false, nil, fmt.Errorf("usage: amberctl init [--yes] [--wizard] [--cells ftp,smtp,…]")
		default:
			return false, false, nil, fmt.Errorf("init: unexpected argument %q (try --yes, --wizard, --cells)", a)
		}
	}
	if len(cells) > 0 {
		// --cells always implies wizard intent (caller rejects --yes/--wizard conflict).
		forceWizard = true
	}
	return yes, forceWizard, cells, nil
}

func splitCells(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := compose.Cells[p]; !ok {
			return nil, fmt.Errorf("init: unknown cell %q", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("init: --cells requires at least one service")
	}
	return out, nil
}
