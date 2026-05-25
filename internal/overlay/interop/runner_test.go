package interop

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vectorRoot returns the absolute path to docs/internal/conformance-vectors/.
// The test file lives at internal/overlay/interop/runner_test.go, so the
// relative path is "../../../docs/internal/conformance-vectors".
func vectorRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../../../docs/internal/conformance-vectors")
	if err != nil {
		t.Fatalf("resolve vector root: %v", err)
	}
	return abs
}

// expectedFiles describes the pinned corpus (ts-stack commit 29aff6e2,
// docs/internal/conformance-vectors/PIN.md). If this drifts the snapshot has
// moved without PIN.md being updated.
var expectedFiles = map[string]int{
	"auth.brc31-handshake":    16,
	"overlay.lookup":          14,
	"overlay.submit":          12,
	"overlay.topicmanagement": 18,
	"sync.gasprotocol":        20,
}

const expectedTotal = 16 + 14 + 12 + 18 + 20 // 80

func TestLoadAll_FindsAllPinnedVectors(t *testing.T) {
	files, err := LoadAll(vectorRoot(t))
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	if len(files) != len(expectedFiles) {
		t.Fatalf("loaded %d files, want %d. Loaded IDs: %v",
			len(files), len(expectedFiles), fileIDs(files))
	}

	for _, f := range files {
		want, ok := expectedFiles[f.ID]
		if !ok {
			t.Errorf("unexpected file ID loaded: %s (from %s)", f.ID, f.SourcePath)
			continue
		}
		if len(f.Vectors) != want {
			t.Errorf("file %s: got %d vectors, want %d", f.ID, len(f.Vectors), want)
		}
	}

	if total := TotalVectors(files); total != expectedTotal {
		t.Errorf("TotalVectors = %d, want %d", total, expectedTotal)
	}
}

func TestLoadAll_RejectsEmptyVectorArray(t *testing.T) {
	// A valid vector file MUST contain at least one vector. The loader treats
	// an empty vectors array as a corrupted snapshot rather than silently
	// loading nothing. This guards against silent under-coverage.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bad.json")
	body := `{"id":"x","name":"x","version":"0.0.0","reference_impl":"x","parity_class":"required","vectors":[]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAll(tmp); err == nil {
		t.Fatal("expected error for empty vectors array, got nil")
	}
}

func TestRun_AllPendingInPhase0a(t *testing.T) {
	// Phase 0a expectation: no dispatchers registered, every active vector
	// returns StatusPending, no PASS/FAIL/ERROR. As workstreams land, real
	// dispatchers register and convert PENDING to PASS/FAIL/SKIP.
	files, err := LoadAll(vectorRoot(t))
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	reg := NewRegistry()

	report := Run(context.Background(), files, reg)

	if report.Fail != 0 {
		t.Errorf("Phase 0a expected 0 FAIL, got %d", report.Fail)
	}
	if report.Error != 0 {
		t.Errorf("Phase 0a expected 0 ERROR, got %d", report.Error)
	}
	if report.Pass != 0 {
		t.Errorf("Phase 0a expected 0 PASS (no dispatchers registered), got %d", report.Pass)
	}

	wantPending := ActiveVectors(files)
	if report.Pending != wantPending {
		t.Errorf("Phase 0a expected %d PENDING (= ActiveVectors), got %d", wantPending, report.Pending)
	}

	if report.Skip != 0 {
		t.Logf("note: %d vectors carry skip=true; check if pin moved", report.Skip)
	}

	// Every workstream that owns a vector file in the pinned corpus must show
	// up in the pending-by-workstream breakdown.
	pending := report.PendingByWorkstream()
	for _, ws := range []string{"A", "A+B", "A+C", "A+D", "E"} {
		if pending[ws] == 0 {
			t.Errorf("expected pending vectors for workstream %q, got 0", ws)
		}
	}
}

func TestFormatSummary_StableShape(t *testing.T) {
	files, err := LoadAll(vectorRoot(t))
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	reg := NewRegistry()
	report := Run(context.Background(), files, reg)

	var buf1, buf2 bytes.Buffer
	FormatSummary(&buf1, files, report)
	FormatSummary(&buf2, files, report)

	if buf1.String() != buf2.String() {
		t.Error("FormatSummary output is unstable across runs (map iteration leak?)")
		t.Logf("first run:\n%s", buf1.String())
		t.Logf("second run:\n%s", buf2.String())
	}

	out := buf1.String()
	for _, want := range []string{
		"Anvil Conformance Runner",
		"Files loaded: 5",
		"Total vectors: 80",
		"PENDING:",
		"Pending dispatchers by workstream:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("FormatSummary output missing %q.\nFull output:\n%s", want, out)
		}
	}
}

func TestRegistry_RejectsDoubleRegister(t *testing.T) {
	reg := NewRegistry()
	d := &fakeDispatcher{id: "overlay.submit"}
	if err := reg.Register(d); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := reg.Register(d); err == nil {
		t.Fatal("expected error on duplicate Register, got nil")
	}
}

func TestRegistry_DispatcherInvoked(t *testing.T) {
	// Proves that when a dispatcher IS registered, Run uses it. Validates the
	// wiring before any real dispatcher lands in Workstream A.
	files, err := LoadAll(vectorRoot(t))
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	reg := NewRegistry()
	d := &fakeDispatcher{id: "overlay.submit", returnStatus: StatusPass}
	if err := reg.Register(d); err != nil {
		t.Fatalf("Register: %v", err)
	}

	report := Run(context.Background(), files, reg)

	wantSubmitCount := expectedFiles["overlay.submit"]
	if report.Pass != wantSubmitCount {
		t.Errorf("Pass = %d, want %d (overlay.submit vectors)", report.Pass, wantSubmitCount)
	}
	if !d.invoked {
		t.Error("fakeDispatcher was not invoked")
	}
}

func TestSafeRun_RecoversPanic(t *testing.T) {
	files, err := LoadAll(vectorRoot(t))
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	reg := NewRegistry()
	if err := reg.Register(&panickyDispatcher{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	report := Run(context.Background(), files, reg)

	if report.Error != expectedFiles["sync.gasprotocol"] {
		t.Errorf("Error count = %d, want %d (one ERROR per sync.gasprotocol vector)",
			report.Error, expectedFiles["sync.gasprotocol"])
	}
}

// --- helpers ---

type fakeDispatcher struct {
	id           string
	returnStatus Status
	invoked      bool
}

func (f *fakeDispatcher) FileID() string { return f.id }
func (f *fakeDispatcher) Run(_ context.Context, file *VectorFile, v Vector) Result {
	f.invoked = true
	st := f.returnStatus
	if st == "" {
		st = StatusPass
	}
	return Result{
		FileID:     file.ID,
		VectorID:   v.ID,
		Status:     st,
		Workstream: workstreamForFile(file.ID),
	}
}

type panickyDispatcher struct{}

func (p *panickyDispatcher) FileID() string { return "sync.gasprotocol" }
func (p *panickyDispatcher) Run(_ context.Context, _ *VectorFile, _ Vector) Result {
	panic("simulated dispatcher crash")
}

func fileIDs(files []*VectorFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.ID)
	}
	return out
}
