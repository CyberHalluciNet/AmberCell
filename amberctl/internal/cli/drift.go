// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/canary"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

type cellState struct {
	ProviderID    string `json:"provider_id"`
	ImageDigest   string `json:"image_digest"`
	HiImageDigest string `json:"hi_image_digest"`
}

func runStatusDrift() error {
	root, err := paths.FindComposeRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: compose root: %v\n", err)
	}

	var failed bool
	for _, svc := range []string{
		"ftp", "telnet", "smtp", "pop3", "ssh", "redis", "mqtt",
		"http", "mysql", "postgres", "smb", "mongo", "elastic",
		"dockerapi", "kubelet", "ollama",
	} {
		if err := driftOne(svc, root); err != nil {
			fmt.Fprintf(os.Stderr, "drift %s: %v\n", svc, err)
			failed = true
		}
	}

	// nft + compose + policy hashes (global)
	if root != "" {
		for _, rel := range []string{"nftables/ingress.nft", "nftables/egress.nft", "compose.yaml", "compose.lab.yaml"} {
			sum, err := fileSHA256(filepath.Join(root, rel))
			if err != nil {
				fmt.Printf("config_hash %s: missing (%v)\n", rel, err)
				failed = true
			} else {
				fmt.Printf("config_hash %s: %s\n", rel, sum[:16]+"…")
			}
		}
		polDir := filepath.Join(root, "manager", "policies")
		entries, _ := os.ReadDir(polDir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			p := filepath.Join(polDir, e.Name())
			sum, err := fileSHA256(p)
			if err != nil {
				failed = true
				continue
			}
			fmt.Printf("policy_hash %s: %s\n", e.Name(), sum[:16]+"…")
		}
		if exp := os.Getenv("AMBER_EXPECT_COMPOSE_HASH"); exp != "" {
			sum, err := fileSHA256(filepath.Join(root, "compose.yaml"))
			if err != nil || !strings.HasPrefix(sum, exp) {
				fmt.Fprintf(os.Stderr, "drift: compose.yaml hash mismatch (expected prefix %s)\n", exp)
				failed = true
			}
		}
	}

	if failed {
		return exitErr(1, "drift: one or more checks failed")
	}
	return nil
}

func driftOne(svc, root string) error {
	spec, ok := compose.Cells[svc]
	if !ok {
		return fmt.Errorf("unknown svc")
	}
	statePath := filepath.Join(paths.EvidenceRoot(), "state", svc+".json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("--- drift (%s): state missing (cell not up?) ---\n", svc)
			return nil
		}
		return err
	}
	var st cellState
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}

	expected := spec.DefaultProv
	if p := strings.TrimSpace(os.Getenv(spec.ProviderEnv)); p != "" {
		expected = p
	}
	actual := strings.TrimSpace(st.ProviderID)

	fmt.Printf("--- drift (%s) ---\n", svc)
	fmt.Printf("compose_expected_provider: %s\n", expected)
	fmt.Printf("state_provider_id:         %s\n", actual)
	fmt.Printf("image_digest:              %s\n", st.ImageDigest)
	fmt.Printf("hi_image_digest:           %s\n", st.HiImageDigest)

	manPath := canary.ManifestPath(svc)
	if md, err := os.ReadFile(manPath); err == nil {
		sum := sha256.Sum256(md)
		fmt.Printf("seed_manifest:             %s sha256=%s\n", manPath, hex.EncodeToString(sum[:])[:16]+"…")
	} else {
		fmt.Printf("seed_manifest:             missing (%s)\n", manPath)
	}

	if actual == "" {
		return fmt.Errorf("state provider_id missing")
	}
	if actual != expected {
		return fmt.Errorf("provider mismatch (expected %q, state %q)", expected, actual)
	}
	_ = root
	return nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
