// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package replay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Volatile fields are ignored when diffing records (anti-flake for lab regen).
var DefaultIgnoreFields = map[string]bool{
	"ts": true, "event_id": true, "artifact_id": true, "decision_id": true,
	"first_seen": true, "last_seen": true, "pcap_ref": true,
}

type Record struct {
	SeqID  int64
	Raw    map[string]any
	LineNo int
}

type DiffEntry struct {
	SeqID   int64
	Kind    string // missing_actual | missing_golden | mismatch
	Golden  map[string]any
	Actual  map[string]any
	Details []string
}

type DiffResult struct {
	GoldenCount int
	ActualCount int
	Diffs       []DiffEntry
	Metrics     ConsistencyMetrics
}

type ConsistencyMetrics struct {
	PolicyVersion string
	PolicyRefs    []string
	DecisionVersion string
	Matched       int
	Mismatched    int
	MissingGolden int
	MissingActual int
}

// LoadJSONL reads newline-delimited JSON objects from path.
func LoadJSONL(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		seq, err := seqID(raw)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		out = append(out, Record{SeqID: seq, Raw: raw, LineNo: lineNo})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SeqID < out[j].SeqID })
	return out, nil
}

func seqID(raw map[string]any) (int64, error) {
	v, ok := raw["seq_id"]
	if !ok {
		return 0, fmt.Errorf("missing seq_id")
	}
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case json.Number:
		i, err := n.Int64()
		return i, err
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("seq_id has unsupported type %T", v)
	}
}

func indexBySeq(recs []Record) map[int64]Record {
	m := make(map[int64]Record, len(recs))
	for _, r := range recs {
		m[r.SeqID] = r
	}
	return m
}

func stripIgnored(raw map[string]any, ignore map[string]bool) map[string]any {
	out := make(map[string]any, len(raw))
	for k, v := range raw {
		if ignore[k] {
			continue
		}
		out[k] = v
	}
	return out
}

func compareMaps(g, a map[string]any) []string {
	gb, _ := json.Marshal(stripIgnored(g, DefaultIgnoreFields))
	ab, _ := json.Marshal(stripIgnored(a, DefaultIgnoreFields))
	if string(gb) == string(ab) {
		return nil
	}
	var details []string
	keys := map[string]bool{}
	for k := range g {
		keys[k] = true
	}
	for k := range a {
		keys[k] = true
	}
	for k := range keys {
		if DefaultIgnoreFields[k] {
			continue
		}
		gv, gok := g[k]
		av, aok := a[k]
		if !gok && aok {
			details = append(details, fmt.Sprintf("field %q only in actual", k))
		} else if gok && !aok {
			details = append(details, fmt.Sprintf("field %q only in golden", k))
		} else if fmt.Sprint(gv) != fmt.Sprint(av) {
			details = append(details, fmt.Sprintf("field %q: golden=%v actual=%v", k, gv, av))
		}
	}
	sort.Strings(details)
	return details
}

// Diff compares golden vs actual JSONL sorted by seq_id.
func Diff(goldenPath, actualPath string) (*DiffResult, error) {
	golden, err := LoadJSONL(goldenPath)
	if err != nil {
		return nil, fmt.Errorf("golden: %w", err)
	}
	actual, err := LoadJSONL(actualPath)
	if err != nil {
		return nil, fmt.Errorf("actual: %w", err)
	}
	aIdx := indexBySeq(actual)

	res := &DiffResult{GoldenCount: len(golden), ActualCount: len(actual)}
	seen := map[int64]bool{}

	for _, g := range golden {
		seen[g.SeqID] = true
		a, ok := aIdx[g.SeqID]
		if !ok {
			res.Diffs = append(res.Diffs, DiffEntry{
				SeqID: g.SeqID, Kind: "missing_actual", Golden: g.Raw,
			})
			res.Metrics.MissingActual++
			continue
		}
		if details := compareMaps(g.Raw, a.Raw); len(details) > 0 {
			res.Diffs = append(res.Diffs, DiffEntry{
				SeqID: g.SeqID, Kind: "mismatch", Golden: g.Raw, Actual: a.Raw, Details: details,
			})
			res.Metrics.Mismatched++
		} else {
			res.Metrics.Matched++
		}
	}
	for _, a := range actual {
		if seen[a.SeqID] {
			continue
		}
		res.Diffs = append(res.Diffs, DiffEntry{
			SeqID: a.SeqID, Kind: "missing_golden", Actual: a.Raw,
		})
		res.Metrics.MissingGolden++
	}
	sort.Slice(res.Diffs, func(i, j int) bool { return res.Diffs[i].SeqID < res.Diffs[j].SeqID })
	res.Metrics = enrichDecisionMetrics(golden, actual, res.Metrics)
	return res, nil
}

func enrichDecisionMetrics(golden, actual []Record, m ConsistencyMetrics) ConsistencyMetrics {
	for _, r := range golden {
		if r.Raw["schema_version"] != "decision.v1" {
			continue
		}
		if dv, ok := r.Raw["decision_version"].(string); ok && m.DecisionVersion == "" {
			m.DecisionVersion = dv
		}
		if refs, ok := r.Raw["policy_refs"].([]any); ok && len(m.PolicyRefs) == 0 {
			for _, ref := range refs {
				if s, ok := ref.(string); ok {
					m.PolicyRefs = append(m.PolicyRefs, s)
				}
			}
		}
	}
	_ = actual
	if m.DecisionVersion != "" && len(m.PolicyRefs) > 0 {
		m.PolicyVersion = m.DecisionVersion + "+" + strings.Join(m.PolicyRefs, ",")
	}
	return m
}

func (r *DiffResult) OK() bool {
	return len(r.Diffs) == 0
}
