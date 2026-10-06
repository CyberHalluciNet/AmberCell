// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package webhook

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSpillOnMissingURLNoOp(t *testing.T) {
	r := &Router{url: "", ch: make(chan Alert, 1)}
	r.Enqueue(Alert{AlertID: "t1", Summary: "test"})
}

func TestSpillWritesFailedDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AMBER_EVIDENCE_ROOT", tmp)
	r := &Router{url: "http://127.0.0.1:1", ch: make(chan Alert, 1), client: Default().client}
	a := Alert{AlertID: "spill-test", Summary: "boom"}
	if err := r.spill(a, "unit_test"); err != nil {
		t.Fatal(err)
	}
	glob, _ := filepath.Glob(filepath.Join(tmp, "alerts", "failed", "*.json"))
	if len(glob) != 1 {
		t.Fatalf("expected one spill file, got %v", glob)
	}
}

func TestBreakerOpensAfterFailures(t *testing.T) {
	r := &Router{url: "http://127.0.0.1:1", ch: make(chan Alert, 4), client: Default().client}
	for i := 0; i < maxFailsBeforeDegrade; i++ {
		r.recordFailure(Alert{AlertID: "x"}, os.ErrDeadlineExceeded)
	}
	if !r.Degraded() {
		t.Fatal("expected degraded after max failures")
	}
}

func TestEnqueueNonBlocking(t *testing.T) {
	r := &Router{
		url:    "http://example.invalid",
		ch:     make(chan Alert, queueCapacity),
		client: &http.Client{Timeout: 50 * time.Millisecond},
	}
	r.once.Do(r.startWorker)
	start := time.Now()
	for i := 0; i < 20; i++ {
		r.Enqueue(Alert{AlertID: "nb", Summary: "fast"})
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("Enqueue blocked caller")
	}
}
