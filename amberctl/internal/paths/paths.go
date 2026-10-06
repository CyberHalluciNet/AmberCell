// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package paths

import (
	"os"
	"path/filepath"
)

const defaultEvidenceRoot = "/var/ambercell"

// EvidenceRoot returns AMBER_EVIDENCE_ROOT or the default.
func EvidenceRoot() string {
	if v := os.Getenv("AMBER_EVIDENCE_ROOT"); v != "" {
		return v
	}
	return defaultEvidenceRoot
}

// InitSubdirs are created by amberctl init.
var InitSubdirs = []string{
	"raw-flows",
	"jsonl",
	"pcap",
	"artifacts",
	"transcripts",
	"enrichment",
	"state",
	"deaddrop",
	"alerts",
	"decisions",
}

const InitMarker = ".ambercell-initialized"

// FindComposeRoot returns the directory containing compose.yaml.
func FindComposeRoot() (string, error) {
	if root := os.Getenv("AMBER_ROOT"); root != "" {
		if fileExists(filepath.Join(root, "compose.yaml")) {
			return root, nil
		}
		return "", &ComposeNotFoundError{Hint: "AMBER_ROOT set but compose.yaml missing"}
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if fileExists(filepath.Join(dir, "compose.yaml")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", &ComposeNotFoundError{Hint: "set AMBER_ROOT or run from repo tree"}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ComposeNotFoundError is returned when compose.yaml cannot be located.
type ComposeNotFoundError struct {
	Hint string
}

func (e *ComposeNotFoundError) Error() string {
	return "compose.yaml not found: " + e.Hint
}
