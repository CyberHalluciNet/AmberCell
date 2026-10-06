// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

// Package nftables applies AmberCell host nftables rules and quarantine set ops.
package nftables

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Apply loads ingress then egress rules from the repo nftables/ directory.
// No-op (logged) on non-Linux unless AMBER_FORCE_NFT=1.
func Apply(repoRoot string) error {
	if runtime.GOOS != "linux" && os.Getenv("AMBER_FORCE_NFT") != "1" {
		fmt.Fprintf(os.Stderr, "amberctl: nft apply stub (GOOS=%s): would load nftables/ingress.nft + egress.nft\n", runtime.GOOS)
		return nil
	}
	ingress := filepath.Join(repoRoot, "nftables", "ingress.nft")
	egress := filepath.Join(repoRoot, "nftables", "egress.nft")
	for _, f := range []string{ingress, egress} {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("nftables: missing %s: %w", f, err)
		}
	}
	// Unload FTP helper before apply (PASV-only; reduces reflection risk).
	_ = exec.Command("modprobe", "-r", "nf_conntrack_ftp").Run()

	for _, f := range []string{ingress, egress} {
		cmd := exec.Command("nft", "-f", f)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("nft -f %s: %w", f, err)
		}
		fmt.Fprintf(os.Stderr, "amberctl: nft applied %s\n", f)
	}
	return nil
}

// QuarantineAdd inserts a cell IP into inet ambercell amber_quarantine.
func QuarantineAdd(cellIP string) error {
	return quarantineOp("add", cellIP)
}

// QuarantineDelete removes a cell IP from amber_quarantine.
func QuarantineDelete(cellIP string) error {
	return quarantineOp("delete", cellIP)
}

func quarantineOp(op, cellIP string) error {
	cellIP = strings.TrimSpace(cellIP)
	if cellIP == "" {
		return fmt.Errorf("nftables: empty cell IP for quarantine %s", op)
	}
	args := []string{op, "element", "inet", "ambercell", "amber_quarantine", "{", cellIP, "}"}
	line := "nft " + strings.Join(args, " ")
	if runtime.GOOS != "linux" && os.Getenv("AMBER_FORCE_NFT") != "1" {
		fmt.Fprintf(os.Stderr, "amberctl: quarantine stub (GOOS=%s): would run: %s\n", runtime.GOOS, line)
		return nil
	}
	cmd := exec.Command("nft", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", line, err)
	}
	fmt.Fprintf(os.Stderr, "amberctl: quarantine %s %s\n", op, cellIP)
	return nil
}
