// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

func runCritic(args []string) error {
	fs := flag.NewFlagSet("critic", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	decisionPath := fs.String("decision", "", "path to decision.v1 JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := *decisionPath
	if path == "" && len(fs.Args()) > 0 {
		path = fs.Args()[0]
	}
	if path == "" {
		return fmt.Errorf("usage: amberctl critic --decision PATH")
	}

	root, err := paths.FindComposeRoot()
	if err != nil {
		return err
	}
	script := filepath.Join(root, "manager", "critic.py")
	cmd := exec.Command("python3", script, path)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exitErr(exit.ExitCode(), "critic failed")
		}
		return err
	}
	return nil
}
