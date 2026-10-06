// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
)

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outDir := fs.String("out", "", "export destination (default: $AMBER_EVIDENCE_ROOT/export)")
	live := fs.Bool("live", false, "read active JSONL tail (not available in Stage-0B)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *live {
		fmt.Fprintln(os.Stderr, "export: --live reads active JSONL tails (debug only; may tear lines)")
	}

	evidence := paths.EvidenceRoot()
	dest := *outDir
	if dest == "" {
		dest = filepath.Join(evidence, "export")
	}
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return fmt.Errorf("export: mkdir %s: %w", dest, err)
	}

	jsonlRoot := filepath.Join(evidence, "jsonl")
	if _, err := os.Stat(jsonlRoot); os.IsNotExist(err) {
		fmt.Println("export: no closed JSONL segments found (jsonl/ missing)")
		return nil
	}
	var segments []string
	var err error
	if *live {
		segments, err = liveJSONLSegments(jsonlRoot)
	} else {
		segments, err = closedJSONLSegments(jsonlRoot)
	}
	if err != nil {
		return err
	}
	if len(segments) == 0 {
		if *live {
			fmt.Println("export: no JSONL segments found")
		} else {
			fmt.Println("export: no closed JSONL segments found")
		}
		return nil
	}

	if err := assertCompatibleSchemaMajors(segments); err != nil {
		return err
	}

	for _, src := range segments {
		rel, err := filepath.Rel(evidence, src)
		if err != nil {
			rel = filepath.Base(src)
		}
		dst := filepath.Join(dest, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return fmt.Errorf("export: mkdir: %w", err)
		}
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("export: copy %s: %w", src, err)
		}
		fmt.Println(src)
	}
	return nil
}

func closedJSONLSegments(jsonlRoot string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(jsonlRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, ".jsonl.active") {
			return nil
		}
		if !isClosedJSONLSegment(name) {
			return nil
		}
		if refusePlainJSONLWithActive(path, name) {
			return nil
		}
		if isSymlinkToActive(path) {
			return nil
		}
		lockPath := path + ".lock"
		if _, err := os.Stat(lockPath); err == nil {
			return exitErr(1, "export: refusing to read %s while sibling lock %s exists", path, lockPath)
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		if _, ok := err.(*ExitError); ok {
			return nil, err
		}
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return out, nil
}

func liveJSONLSegments(jsonlRoot string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(jsonlRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		name := d.Name()
		if strings.HasSuffix(name, ".jsonl.active") || strings.HasSuffix(name, ".jsonl") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

// isClosedJSONLSegment identifies exportable JSONL (closed/rotated only).
func isClosedJSONLSegment(name string) bool {
	if strings.HasSuffix(name, ".jsonl.active") {
		return false
	}
	if strings.Contains(name, ".jsonl.") {
		return true
	}
	return strings.HasSuffix(name, ".jsonl")
}

func refusePlainJSONLWithActive(path, name string) bool {
	if !strings.HasSuffix(name, ".jsonl") || strings.Contains(name, ".jsonl.") {
		return false
	}
	active := path + ".active"
	if _, err := os.Stat(active); err == nil {
		return true
	}
	return false
}

func isSymlinkToActive(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(path)
	if err != nil {
		return false
	}
	return strings.HasSuffix(target, ".active")
}

func assertCompatibleSchemaMajors(segments []string) error {
	majors := map[string]bool{}
	for _, src := range segments {
		f, err := os.Open(src)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				_ = f.Close()
				return fmt.Errorf("export: invalid JSONL in %s: %w", src, err)
			}
			sv, _ := obj["schema_version"].(string)
			if sv == "" {
				continue
			}
			major := sv
			if i := strings.Index(sv, "."); i > 0 {
				major = sv[:i]
			}
			majors[major] = true
			break
		}
		_ = f.Close()
	}
	if len(majors) > 1 && os.Getenv("AMBER_EXPORT_ALLOW_MIXED_SCHEMA") != "1" {
		return exitErr(1, "export: mixed schema majors in bundle (%d types); set AMBER_EXPORT_ALLOW_MIXED_SCHEMA=1 to override", len(majors))
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()
	_, err = io.Copy(out, in)
	return err
}
