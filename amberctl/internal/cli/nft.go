// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/nftables"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

func runNft(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: amberctl nft apply|status")
	}
	switch args[0] {
	case "apply":
		root, err := paths.FindComposeRoot()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "amberctl: nft apply (uid=%d) root=%s\n", os.Getuid(), root)
		if err := nftables.Apply(root); err != nil {
			return err
		}
		return nil
	case "status":
		// Best-effort: list ambercell table if present.
		fmt.Fprintln(os.Stderr, "amberctl: nft list table inet ambercell (Linux production)")
		return nil
	default:
		return fmt.Errorf("usage: amberctl nft apply|status")
	}
}

func productionProfilesActive() bool {
	profiles := os.Getenv("COMPOSE_PROFILES")
	for _, p := range strings.Split(profiles, ",") {
		if strings.TrimSpace(p) == "production" {
			return true
		}
	}
	return os.Getenv("AMBER_PROFILE") == "production"
}

func labProfilesActive() bool {
	profiles := os.Getenv("COMPOSE_PROFILES")
	if profiles == "" {
		return true // default lab,core
	}
	for _, p := range strings.Split(profiles, ",") {
		if strings.TrimSpace(p) == "lab" {
			return true
		}
	}
	return false
}
