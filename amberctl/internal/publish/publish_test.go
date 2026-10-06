// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package publish

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRedactJSONLStreamFlushesFinalLineWithoutTrailingNewline(t *testing.T) {
	input := `{"user":"alice","password":"secret"}`

	var out strings.Builder
	if err := redactJSONLStream(strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	if !strings.Contains(got, `"password":"[redacted]"`) {
		t.Fatalf("expected redacted password in output, got %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("expected newline-terminated JSONL output, got %q", got)
	}
}

func TestPublishSummaryIncludesAlerts(t *testing.T) {
	evidence := t.TempDir()
	bundleDir := filepath.Join(evidence, "deaddrop", "bundle")

	for _, dir := range []string{
		filepath.Join(evidence, "decisions", "ftp"),
		filepath.Join(evidence, "enrichment", "ftp"),
		filepath.Join(evidence, "alerts", "pending"),
		filepath.Join(evidence, "raw-flows", "ftp"),
		filepath.Join(evidence, "jsonl", "ftp"),
	} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	fixtures := map[string]string{
		filepath.Join(evidence, "decisions", "ftp", "decision.json"):    `{"schema_version":"decision.v1"}` + "\n",
		filepath.Join(evidence, "enrichment", "ftp", "enrichment.json"): `{"schema_version":"enrichment.v1"}` + "\n",
		filepath.Join(evidence, "alerts", "pending", "alert.json"):      `{"schema_version":"alert.v1"}` + "\n",
		filepath.Join(evidence, "raw-flows", "ftp", "events.jsonl"):     `{"schema_version":"rawflow.v1"}` + "\n",
		filepath.Join(evidence, "jsonl", "ftp", "events.jsonl"):         `{"schema_version":"event.v1","password":"secret"}` + "\n",
	}
	for path, contents := range fixtures {
		if err := os.WriteFile(path, []byte(contents), 0o640); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := publishSummary(evidence, bundleDir, Options{Class: ClassSummary})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected summary publish entries")
	}

	alertCopy := filepath.Join(bundleDir, "alerts", "pending", "alert.json")
	if _, err := os.Stat(alertCopy); err != nil {
		t.Fatalf("expected alert copy in summary bundle: %v", err)
	}
}

func TestTryS3UploadRetriesWithFreshCommand(t *testing.T) {
	tmp := t.TempDir()
	bundleDir := filepath.Join(tmp, "bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	countFile := filepath.Join(tmp, "aws-count")
	scriptPath := filepath.Join(tmp, "aws")
	script := "#!/bin/sh\n" +
		"count=0\n" +
		"if [ -f \"" + countFile + "\" ]; then count=$(cat \"" + countFile + "\"); fi\n" +
		"count=$((count+1))\n" +
		"printf '%s' \"$count\" > \"" + countFile + "\"\n" +
		"if [ \"$count\" -eq 1 ]; then exit 1; fi\n" +
		"exit 0\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	oldDelay := s3RetryDelay
	s3RetryDelay = time.Millisecond
	t.Cleanup(func() {
		s3RetryDelay = oldDelay
	})

	t.Setenv("AMBER_DEADDROP_S3_URI", "s3://ambercell-test")
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))

	tryS3Upload(bundleDir)

	raw, err := os.ReadFile(countFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "2" {
		t.Fatalf("expected two aws invocations, got %q", string(raw))
	}
}
