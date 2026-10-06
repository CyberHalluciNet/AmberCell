// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package canary

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

const Prefix = "AMBERCANARY_"

type ManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"`
}

type SeedManifest struct {
	SchemaVersion string                    `json:"schema_version"`
	Svc           string                    `json:"svc"`
	GeneratedAt   string                    `json:"generated_at"`
	Prefix        string                    `json:"canary_prefix"`
	Entries       map[string]ManifestEntry `json:"entries"`
}

// Generate writes dynamic canaries + seed_manifest.json under evidence state/.
func Generate(svc string) (*SeedManifest, error) {
	root := paths.EvidenceRoot()
	canaryDir := filepath.Join(root, "state", "canaries", svc)
	if err := os.MkdirAll(canaryDir, 0o750); err != nil {
		return nil, err
	}

	token, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	pass, err := randomHex(8)
	if err != nil {
		return nil, err
	}

	values := map[string]string{
		"upload_token": Prefix + svc + "_upload_" + token,
		"weak_password": Prefix + svc + "_pass_" + pass,
		"api_key":      Prefix + svc + "_key_" + token[:12],
	}

	entries := map[string]ManifestEntry{}
	for name, val := range values {
		rel := filepath.Join("state", "canaries", svc, name+".txt")
		abs := filepath.Join(root, rel)
		if err := os.WriteFile(abs, []byte(val+"\n"), 0o640); err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(val + "\n"))
		entries[name] = ManifestEntry{
			Path:   rel,
			SHA256: hex.EncodeToString(sum[:]),
			Kind:   "canary",
		}
	}

	// Note ownership/mode for operators (lab may not chown to root:amber).
	notesPath := filepath.Join(root, "state", "permissions.notes")
	_ = os.WriteFile(notesPath, []byte(
		"/var/ambercell mode 0750 owner root group amber (production).\n"+
			"Lab trees under AMBER_EVIDENCE_ROOT inherit the invoking uid; apply chown/chmod on Linux hosts.\n"+
			"Canary values always use prefix "+Prefix+" — never live credentials.\n",
	), 0o640)

	manifest := &SeedManifest{
		SchemaVersion: "seed_manifest.v1",
		Svc:           svc,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Prefix:        Prefix,
		Entries:       entries,
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	out := filepath.Join(root, "state", svc+".seed_manifest.json")
	if err := os.WriteFile(out, append(data, '\n'), 0o640); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "amberctl: wrote canaries + %s\n", out)
	return manifest, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ManifestPath returns the seed manifest path for a service.
func ManifestPath(svc string) string {
	return filepath.Join(paths.EvidenceRoot(), "state", svc+".seed_manifest.json")
}
