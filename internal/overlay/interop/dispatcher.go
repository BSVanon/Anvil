package interop

import (
	"context"
	"fmt"
	"sync"
)

// Status is the outcome of running a single Vector through a Dispatcher.
type Status string

const (
	// StatusPass — dispatcher executed the vector and assertions held.
	StatusPass Status = "PASS"

	// StatusFail — dispatcher executed but assertions did not hold.
	StatusFail Status = "FAIL"

	// StatusSkip — dispatcher recognized the vector but the run skipped it
	// (e.g. Vector.Skip == true, or parity_class == intended without infra).
	StatusSkip Status = "SKIP"

	// StatusPending — no dispatcher is registered for this vector's file ID yet.
	// Used during Phase 0a; should drop to zero as workstreams land.
	StatusPending Status = "PENDING"

	// StatusError — the dispatcher itself crashed (not a clean assertion failure).
	StatusError Status = "ERROR"
)

// Result is one row in a Report.
type Result struct {
	FileID     string
	VectorID   string
	Status     Status
	Message    string // human-readable: what assertion failed or why skipped
	Workstream string // alignment-plan workstream that owns this vector ("A", "B", "C", "D", "E", "F", "G")
}

// Dispatcher runs the vectors for one VectorFile.id (e.g. "overlay.submit").
// Implementations live next to the subsystem under test:
//   - Workstream A adds dispatchers for auth.brc31-handshake, overlay.topicmanagement (health/admin)
//   - Workstream B adds the overlay.submit dispatcher
//   - Workstream C adds the overlay.lookup dispatcher
//   - Workstream D adds remaining topicmanagement (SHIP/SLAP) vectors
//   - Workstream E adds the sync.gasprotocol dispatcher
//
// During Phase 0a, no dispatchers are registered. All vectors land as
// StatusPending so the runner shape can be validated and dispatcher gaps
// quantified.
type Dispatcher interface {
	// FileID is the VectorFile.ID this dispatcher claims (e.g. "overlay.submit").
	FileID() string

	// Run executes the vector and returns a Result. Run MUST NOT panic; on
	// internal errors return StatusError with an explanatory Message.
	Run(ctx context.Context, file *VectorFile, vector Vector) Result
}

// Registry holds the active dispatchers, keyed by VectorFile.ID.
type Registry struct {
	mu          sync.RWMutex
	dispatchers map[string]Dispatcher
}

// NewRegistry returns an empty registry. Call Register to add dispatchers.
func NewRegistry() *Registry {
	return &Registry{dispatchers: make(map[string]Dispatcher)}
}

// Register adds a dispatcher. Errors if the FileID is already claimed.
func (r *Registry) Register(d Dispatcher) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := d.FileID()
	if _, exists := r.dispatchers[id]; exists {
		return fmt.Errorf("dispatcher already registered for file id %q", id)
	}
	r.dispatchers[id] = d
	return nil
}

// Lookup returns the dispatcher for fileID, or nil if none registered.
func (r *Registry) Lookup(fileID string) Dispatcher {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.dispatchers[fileID]
}

// RegisteredIDs returns the FileIDs currently claimed, sorted.
func (r *Registry) RegisteredIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.dispatchers))
	for id := range r.dispatchers {
		ids = append(ids, id)
	}
	// Sort so test output is stable.
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j-1] > ids[j]; j-- {
			ids[j-1], ids[j] = ids[j], ids[j-1]
		}
	}
	return ids
}

// workstreamForFile maps a VectorFile.ID to the alignment-plan workstream
// that owns it. Used by the runner to label Pending results so the report
// shows which workstream needs to land next.
//
// Source: docs/internal/FAILURE_INVENTORY.md §Summary by Workstream.
func workstreamForFile(fileID string) string {
	switch fileID {
	case "auth.brc31-handshake":
		return "A"
	case "overlay.submit":
		return "A+B"
	case "overlay.lookup":
		return "A+C"
	case "overlay.topicmanagement":
		return "A+D"
	case "sync.gasprotocol":
		return "E"
	default:
		return "?"
	}
}

// pendingResult builds a StatusPending result for a vector, labeling which
// workstream owns the dispatcher gap.
func pendingResult(file *VectorFile, v Vector) Result {
	ws := workstreamForFile(file.ID)
	msg := fmt.Sprintf("no dispatcher for file id %q (workstream %s)", file.ID, ws)
	return Result{
		FileID:     file.ID,
		VectorID:   v.ID,
		Status:     StatusPending,
		Message:    msg,
		Workstream: ws,
	}
}
