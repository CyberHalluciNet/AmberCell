// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

// Class controls dead-drop material (summary default per plan).
type Class string

const (
	ClassSummary Class = "summary"
	ClassFull    Class = "full"
)

var s3RetryDelay = 5 * time.Second

// Options for a publish run.
type Options struct {
	Class       Class
	IncludePcap bool
	SvcFilter   string // empty = all core services
}

type manifestEntry struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	SchemaVersion string `json:"schema_version,omitempty"`
	Size          int64  `json:"size_bytes"`
}

type manifest struct {
	SchemaVersion string          `json:"schema_version"`
	PublishClass  string          `json:"publish_class"`
	PublishedAt   string          `json:"published_at"`
	BundleID      string          `json:"bundle_id"`
	Entries       []manifestEntry `json:"entries"`
}

// Run copies closed material into deaddrop/ and writes manifest.json.
func Run(opts Options) (bundleDir string, err error) {
	if opts.Class == "" {
		opts.Class = ClassSummary
	}
	evidence := paths.EvidenceRoot()
	dropRoot := filepath.Join(evidence, "deaddrop")
	ts := time.Now().UTC().Format("20060102T150405Z")
	bundleID := fmt.Sprintf("publish-%s-%s", opts.Class, ts)
	bundleDir = filepath.Join(dropRoot, bundleID)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		return "", err
	}

	var entries []manifestEntry

	switch opts.Class {
	case ClassSummary:
		entries, err = publishSummary(evidence, bundleDir, opts)
	case ClassFull:
		entries, err = publishFull(evidence, bundleDir, opts)
	default:
		return "", fmt.Errorf("publish: unknown class %q", opts.Class)
	}
	if err != nil {
		return "", err
	}

	if opts.IncludePcap {
		pcapEntries, err := copyClosedTree(evidence, bundleDir, "pcap", opts.SvcFilter, nil)
		if err != nil {
			return "", err
		}
		entries = append(entries, pcapEntries...)
	}

	m := manifest{
		SchemaVersion: "deaddrop-manifest.v1",
		PublishClass:  string(opts.Class),
		PublishedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		BundleID:      bundleID,
		Entries:       entries,
	}
	manifestPath := filepath.Join(bundleDir, "manifest.json")
	if err := writeManifest(manifestPath, m); err != nil {
		return "", err
	}

	go tryS3Upload(bundleDir)

	return bundleDir, nil
}

func publishSummary(evidence, bundleDir string, opts Options) ([]manifestEntry, error) {
	var out []manifestEntry
	for _, sub := range []string{"decisions", "enrichment", "alerts"} {
		e, err := copyTree(evidence, bundleDir, sub, opts.SvcFilter, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, e...)
	}
	flows, err := copyClosedTree(evidence, bundleDir, "raw-flows", opts.SvcFilter, nil)
	if err != nil {
		return nil, err
	}
	out = append(out, flows...)
	events, err := copyRedactedJSONL(evidence, bundleDir, opts.SvcFilter)
	if err != nil {
		return nil, err
	}
	out = append(out, events...)
	return out, nil
}

func publishFull(evidence, bundleDir string, opts Options) ([]manifestEntry, error) {
	var out []manifestEntry
	for _, sub := range []string{"decisions", "enrichment", "transcripts", "artifacts"} {
		e, err := copyTree(evidence, bundleDir, sub, opts.SvcFilter, skipActiveSegments)
		if err != nil {
			return nil, err
		}
		out = append(out, e...)
	}
	closed, err := copyClosedTree(evidence, bundleDir, "jsonl", opts.SvcFilter, skipActiveSegments)
	if err != nil {
		return nil, err
	}
	out = append(out, closed...)
	flows, err := copyClosedTree(evidence, bundleDir, "raw-flows", opts.SvcFilter, skipActiveSegments)
	if err != nil {
		return nil, err
	}
	out = append(out, flows...)
	return out, nil
}

func skipActiveSegments(name string) bool {
	return strings.HasSuffix(name, ".jsonl.active") || strings.Contains(name, ".lock")
}

func copyTree(evidence, bundleDir, sub, svcFilter string, skip func(string) bool) ([]manifestEntry, error) {
	srcRoot := filepath.Join(evidence, sub)
	if _, err := os.Stat(srcRoot); os.IsNotExist(err) {
		return nil, nil
	}
	var entries []manifestEntry
	err := filepath.WalkDir(srcRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		if skip != nil && skip(d.Name()) {
			return nil
		}
		if svcFilter != "" && !pathMatchesSvc(path, svcFilter) {
			return nil
		}
		rel, err := filepath.Rel(evidence, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(bundleDir, rel)
		e, err := copyOne(path, dst, rel)
		if err != nil {
			return err
		}
		entries = append(entries, e)
		return nil
	})
	return entries, err
}

func copyClosedTree(evidence, bundleDir, sub, svcFilter string, skip func(string) bool) ([]manifestEntry, error) {
	srcRoot := filepath.Join(evidence, sub)
	if _, err := os.Stat(srcRoot); os.IsNotExist(err) {
		return nil, nil
	}
	var entries []manifestEntry
	err := filepath.WalkDir(srcRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		name := d.Name()
		if strings.HasSuffix(name, ".jsonl.active") {
			return nil
		}
		if skip != nil && skip(name) {
			return nil
		}
		if strings.HasSuffix(name, ".jsonl") && !strings.Contains(name, ".jsonl.") {
			active := path + ".active"
			if _, err := os.Stat(active); err == nil {
				return nil
			}
		}
		if svcFilter != "" && !pathMatchesSvc(path, svcFilter) {
			return nil
		}
		rel, err := filepath.Rel(evidence, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(bundleDir, rel)
		e, err := copyOne(path, dst, rel)
		if err != nil {
			return err
		}
		entries = append(entries, e)
		return nil
	})
	return entries, err
}

func pathMatchesSvc(path, svc string) bool {
	return strings.Contains(filepath.ToSlash(path), "/"+svc+"/") ||
		strings.Contains(filepath.Base(path), svc)
}

var summaryRedactKeys = map[string]bool{
	"password": true, "pass": true, "body": true, "body_preview": true,
	"transcript": true, "data": true, "raw": true,
}

func copyRedactedJSONL(evidence, bundleDir, svcFilter string) ([]manifestEntry, error) {
	srcRoot := filepath.Join(evidence, "jsonl")
	if _, err := os.Stat(srcRoot); os.IsNotExist(err) {
		return nil, nil
	}
	var entries []manifestEntry
	err := filepath.WalkDir(srcRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".jsonl") && !strings.Contains(name, ".jsonl.") {
			return nil
		}
		if strings.HasSuffix(name, ".jsonl.active") {
			return nil
		}
		if strings.HasSuffix(name, ".jsonl") && !strings.Contains(name, ".jsonl.") {
			if _, err := os.Stat(path + ".active"); err == nil {
				return nil
			}
		}
		if svcFilter != "" && !pathMatchesSvc(path, svcFilter) {
			return nil
		}
		rel, err := filepath.Rel(evidence, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(bundleDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		outFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			return err
		}
		defer outFile.Close()
		inFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer inFile.Close()
		h := sha256.New()
		mw := io.MultiWriter(outFile, h)
		if err := redactJSONLStream(inFile, mw); err != nil {
			return err
		}
		sv := ""
		entries = append(entries, manifestEntry{
			Path:          rel,
			SHA256:        hex.EncodeToString(h.Sum(nil)),
			SchemaVersion: sv,
			Size:          fileSize(dst),
		})
		return nil
	})
	return entries, err
}

func redactJSONLStream(in io.Reader, out io.Writer) error {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := in.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				i := indexByteSlice(buf, '\n')
				if i < 0 {
					break
				}
				line := strings.TrimSpace(string(buf[:i]))
				buf = buf[i+1:]
				if line == "" {
					continue
				}
				var obj map[string]any
				if json.Unmarshal([]byte(line), &obj) != nil {
					continue
				}
				redactMap(obj)
				b, _ := json.Marshal(obj)
				if _, werr := out.Write(append(b, '\n')); werr != nil {
					return werr
				}
			}
		}
		if err == io.EOF {
			line := strings.TrimSpace(string(buf))
			if line != "" {
				var obj map[string]any
				if json.Unmarshal([]byte(line), &obj) == nil {
					redactMap(obj)
					b, merr := json.Marshal(obj)
					if merr != nil {
						return merr
					}
					if _, werr := out.Write(append(b, '\n')); werr != nil {
						return werr
					}
				}
			}
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func indexByteSlice(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func redactMap(m map[string]any) {
	for k := range m {
		lk := strings.ToLower(k)
		if summaryRedactKeys[lk] {
			m[k] = "[redacted]"
			continue
		}
		switch v := m[k].(type) {
		case map[string]any:
			redactMap(v)
		}
	}
}

func copyOne(src, dst, relPath string) (manifestEntry, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return manifestEntry{}, err
	}
	in, err := os.Open(src)
	if err != nil {
		return manifestEntry{}, err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return manifestEntry{}, err
	}
	defer out.Close()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		return manifestEntry{}, err
	}
	sv := readFirstSchemaVersion(dst)
	return manifestEntry{
		Path:          filepath.ToSlash(relPath),
		SHA256:        hex.EncodeToString(h.Sum(nil)),
		SchemaVersion: sv,
		Size:          fileSize(dst),
	}, nil
}

func readFirstSchemaVersion(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	line := strings.TrimSpace(string(buf[:n]))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	var obj map[string]any
	if json.Unmarshal([]byte(line), &obj) != nil {
		return ""
	}
	sv, _ := obj["schema_version"].(string)
	return sv
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func writeManifest(path string, m manifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o640)
}

func tryS3Upload(bundleDir string) {
	uri := os.Getenv("AMBER_DEADDROP_S3_URI")
	if uri == "" {
		return
	}
	// Best-effort mirror; failures are logged and retried once — never blocks capture/rebuild.
	if err := newS3SyncCmd(bundleDir, uri).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "amberctl publish: S3 upload failed (will retry once): %v\n", err)
		time.Sleep(s3RetryDelay)
		_ = newS3SyncCmd(bundleDir, uri).Run()
	}
}

func newS3SyncCmd(bundleDir, uri string) *exec.Cmd {
	cmd := exec.Command("aws", "s3", "sync", bundleDir, uri+"/"+filepath.Base(bundleDir)+"/",
		"--sse", "AES256", "--only-show-errors")
	cmd.Env = os.Environ()
	return cmd
}
