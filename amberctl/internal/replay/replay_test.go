// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package replay

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiffBySeqID(t *testing.T) {
	dir := t.TempDir()
	golden := filepath.Join(dir, "golden.jsonl")
	actual := filepath.Join(dir, "actual.jsonl")
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write(golden, `{"seq_id":2,"event":"b","schema_version":"event.v1","ts":"2026-01-01T00:00:00.000000001Z"}
{"seq_id":1,"event":"a","schema_version":"event.v1","ts":"2026-01-02T00:00:00.000000001Z"}
`)
	write(actual, `{"seq_id":1,"event":"a","schema_version":"event.v1","ts":"DIFFERENT"}
{"seq_id":2,"event":"b","schema_version":"event.v1","ts":"2026-01-03T00:00:00.000000001Z"}
`)
	res, err := Diff(golden, actual)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("expected OK diff, got %+v", res.Diffs)
	}
	if res.Metrics.Matched != 2 {
		t.Fatalf("matched=%d want 2", res.Metrics.Matched)
	}
}

func TestDiffMismatch(t *testing.T) {
	dir := t.TempDir()
	golden := filepath.Join(dir, "g.jsonl")
	actual := filepath.Join(dir, "a.jsonl")
	_ = os.WriteFile(golden, []byte(`{"seq_id":1,"event":"auth","ok":false,"schema_version":"event.v1"}`+"\n"), 0o640)
	_ = os.WriteFile(actual, []byte(`{"seq_id":1,"event":"auth","ok":true,"schema_version":"event.v1"}`+"\n"), 0o640)
	res, err := Diff(golden, actual)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("expected mismatch")
	}
	if len(res.Diffs) != 1 || res.Diffs[0].Kind != "mismatch" {
		t.Fatalf("diffs=%+v", res.Diffs)
	}
}
