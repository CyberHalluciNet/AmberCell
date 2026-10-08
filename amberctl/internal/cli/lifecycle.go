// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"fmt"
	"os"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/canary"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
)

const cellUsage = "ftp|telnet|smtp|pop3|ssh|redis|mqtt|http|mysql|postgres|smb|mongo|elastic|dockerapi|kubelet|ollama|dns|tftp|snmp|ntp|syslog|sip|ldap|imap|memcached|rdp|vnc|netbios"

func runUp(args []string) error {
	if len(args) != 1 || !supportedCell(args[0]) {
		return fmt.Errorf("usage: amberctl up %s", cellUsage)
	}
	svc := args[0]
	if productionProfilesActive() {
		if err := ensureProductionPasv(svc); err != nil {
			return err
		}
		if os.Getenv("AMBER_PROFILE") == "" {
			_ = os.Setenv("AMBER_PROFILE", "production")
		}
	}
	if _, err := canary.Generate(svc); err != nil {
		fmt.Fprintf(os.Stderr, "amberctl: canary generate: %v (continuing)\n", err)
	}
	if err := compose.UpCell(svc); err != nil {
		return fmt.Errorf("up %s: %w", svc, err)
	}
	// Production: apply nftables after first cell is up so ambernet bridge exists.
	if productionProfilesActive() && os.Getenv("AMBER_SKIP_NFT_APPLY") != "1" {
		if err := runNft([]string{"apply"}); err != nil {
			fmt.Fprintf(os.Stderr, "amberctl: nft apply after up: %v (set AMBER_SKIP_NFT_APPLY=1 to skip)\n", err)
			return fmt.Errorf("up %s: nft apply: %w", svc, err)
		}
	}
	return nil
}

func ensureProductionPasv(svc string) error {
	if svc != "ftp" {
		return nil
	}
	if os.Getenv("AMBER_FTP_PASV_ADDRESS") == "" {
		return fmt.Errorf("production: set AMBER_FTP_PASV_ADDRESS to the public IPv4 (Internet PASV); refusing lab default 127.0.0.1")
	}
	if os.Getenv("AMBER_FTP_PASV_ADDRESS") == "127.0.0.1" {
		return fmt.Errorf("production: AMBER_FTP_PASV_ADDRESS=127.0.0.1 is invalid for Internet PASV")
	}
	return nil
}

func runDown(args []string) error {
	if len(args) != 1 || !supportedCell(args[0]) {
		return fmt.Errorf("usage: amberctl down %s", cellUsage)
	}
	svc := args[0]
	if err := compose.DownCell(svc); err != nil {
		return fmt.Errorf("down %s: %w", svc, err)
	}
	return nil
}
