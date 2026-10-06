// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunRebuildDefersWhenRecentActivityExists(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AMBER_EVIDENCE_ROOT", tmp)

	eventsDir := filepath.Join(tmp, "jsonl", "ftp")
	if err := os.MkdirAll(eventsDir, 0o750); err != nil {
		t.Fatal(err)
	}

	event := `{"ts":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`
	if err := os.WriteFile(filepath.Join(eventsDir, "events.jsonl"), []byte(event+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	err := runRebuild([]string{"ftp"})
	if err == nil {
		t.Fatal("expected dwell-time guard to defer rebuild")
	}

	var exit *ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exit.Code != 4 {
		t.Fatalf("expected exit code 4, got %d", exit.Code)
	}
	if !strings.Contains(exit.Message, "dwell-time deferred rebuild") {
		t.Fatalf("unexpected message: %q", exit.Message)
	}
}
