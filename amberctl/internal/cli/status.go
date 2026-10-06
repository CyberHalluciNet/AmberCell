// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	drift := fs.Bool("drift", false, "compare providers/seeds/nft hashes vs expected")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: amberctl status [--drift]")
	}
	if *drift {
		return runStatusDrift()
	}
	fmt.Println("--- docker compose ps (project ambercell) ---")
	if err := compose.PS(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: compose ps: %v\n", err)
	}

	for _, svc := range []string{"ftp", "telnet", "smtp", "pop3"} {
		statePath := filepath.Join(paths.EvidenceRoot(), "state", svc+".json")
		data, err := os.ReadFile(statePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "state: %s not present\n", statePath)
				continue
			}
			return fmt.Errorf("status: read state: %w", err)
		}
		fmt.Printf("--- state/%s.json ---\n", svc)
		var pretty map[string]any
		if json.Unmarshal(data, &pretty) == nil {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(pretty)
		} else {
			fmt.Print(string(data))
			if len(data) > 0 && data[len(data)-1] != '\n' {
				fmt.Println()
			}
		}
	}
	return nil
}
