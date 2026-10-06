// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/paths"
	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/replay"
)

func runReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	diff := fs.Bool("diff", false, "compare actual evidence to golden baseline (by seq_id)")
	goldenDir := fs.String("golden-dir", "", "directory of golden baselines (default: repo tests/replay)")
	actual := fs.String("actual", "", "actual JSONL path (default: derive from golden name + evidence root)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	target := ""
	if len(rest) > 0 {
		target = rest[0]
	}
	if *diff {
		if target == "" && *actual == "" {
			return fmt.Errorf("usage: amberctl replay --diff [--actual PATH] <golden.jsonl|case-dir>")
		}
		if target == "" {
			target = *actual
		}
		return runReplayDiff(target, *goldenDir, *actual)
	}
	if target == "" {
		return fmt.Errorf("usage: amberctl replay [--diff] [--actual PATH] <golden.jsonl|case-dir>")
	}
	recs, err := replay.LoadJSONL(target)
	if err != nil {
		return err
	}
	fmt.Printf("replay: %d records (sorted by seq_id) from %s\n", len(recs), target)
	for _, r := range recs {
		fmt.Printf("  seq_id=%d line=%d schema=%v event=%v\n",
			r.SeqID, r.LineNo, r.Raw["schema_version"], r.Raw["event"])
	}
	return nil
}

func runReplayDiff(target, goldenDirOverride, actualOverride string) error {
	goldenPath, err := resolveGoldenPath(target, goldenDirOverride)
	if err != nil {
		return err
	}
	actualPath := actualOverride
	if actualPath == "" {
		actualPath, err = inferActualFromGolden(goldenPath)
		if err != nil {
			return err
		}
	}
	res, err := replay.Diff(goldenPath, actualPath)
	if err != nil {
		return exitErr(2, "replay --diff: %v", err)
	}
	fmt.Printf("replay --diff: golden=%s actual=%s\n", goldenPath, actualPath)
	fmt.Printf("  golden_records=%d actual_records=%d matched=%d mismatched=%d missing_actual=%d missing_golden=%d\n",
		res.GoldenCount, res.ActualCount,
		res.Metrics.Matched, res.Metrics.Mismatched,
		res.Metrics.MissingActual, res.Metrics.MissingGolden,
	)
	if res.Metrics.DecisionVersion != "" || len(res.Metrics.PolicyRefs) > 0 {
		fmt.Printf("  decision_consistency: decision_version=%q policy_refs=%v\n",
			res.Metrics.DecisionVersion, res.Metrics.PolicyRefs)
	}
	for _, d := range res.Diffs {
		fmt.Printf("  diff seq_id=%d kind=%s", d.SeqID, d.Kind)
		if len(d.Details) > 0 {
			fmt.Printf(" details=%v", d.Details)
		}
		fmt.Println()
	}
	if !res.OK() {
		return exitErr(1, "replay --diff: %d difference(s)", len(res.Diffs))
	}
	fmt.Println("replay --diff: OK")
	return nil
}

func resolveGoldenPath(target, goldenDirOverride string) (string, error) {
	if strings.HasSuffix(target, ".jsonl") {
		if _, err := os.Stat(target); err == nil {
			return target, nil
		}
	}
	root, err := paths.FindComposeRoot()
	if err != nil {
		return "", err
	}
	goldenRoot := filepath.Join(root, "tests", "replay")
	if goldenDirOverride != "" {
		goldenRoot = goldenDirOverride
	}
	// case name e.g. ftp/recognized
	candidate := filepath.Join(goldenRoot, target)
	if strings.HasSuffix(candidate, ".jsonl") {
		return candidate, nil
	}
	for _, name := range []string{"events.golden.jsonl", "flows.golden.jsonl", "decision.golden.jsonl"} {
		p := filepath.Join(candidate, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("golden not found for %q under %s", target, goldenRoot)
}

func inferActualFromGolden(goldenPath string) (string, error) {
	base := filepath.Base(goldenPath)
	evidence := paths.EvidenceRoot()
	name := strings.TrimSuffix(base, ".golden.jsonl")
	if name == base {
		name = strings.TrimSuffix(base, ".jsonl")
	}
	// tests/replay/ftp/recognized/events.golden.jsonl → jsonl/ftp/events (closed segments)
	parts := strings.Split(filepath.ToSlash(goldenPath), "/")
	svc := ""
	for i, p := range parts {
		if p == "replay" && i+1 < len(parts) {
			svc = parts[i+1]
			break
		}
	}
	if svc == "" {
		return "", fmt.Errorf("cannot infer svc from golden path %s", goldenPath)
	}
	switch {
	case strings.Contains(base, "flows"):
		return filepath.Join(evidence, "raw-flows", svc, "flows.jsonl"), nil
	case strings.Contains(base, "decision"):
		return filepath.Join(evidence, "decisions", svc, "latest.json"), nil
	default:
		return filepath.Join(evidence, "jsonl", svc, "events.jsonl"), nil
	}
}
