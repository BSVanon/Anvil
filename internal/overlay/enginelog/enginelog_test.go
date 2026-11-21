package enginelog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
)

// recorder is a minimal slog.Handler that records every record it is
// handed, reporting minLevel from Enabled — just enough to drive
// quietCancel's logic without any real log destination.
type recorder struct {
	minLevel slog.Level
	records  []slog.Record
}

func (r *recorder) Enabled(_ context.Context, level slog.Level) bool { return level >= r.minLevel }
func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	r.records = append(r.records, rec)
	return nil
}
func (r *recorder) WithAttrs(_ []slog.Attr) slog.Handler { return r }
func (r *recorder) WithGroup(_ string) slog.Handler      { return r }

// TestWrap_DowngradesCancellationErrorsOnly matches the spec: a cancelled
// or expired context's Error record is downgraded (and, at the inner
// handler's ordinary Info floor, dropped), a genuine error's is not.
func TestWrap_DowngradesCancellationErrorsOnly(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantHandled bool
	}{
		{"context canceled", context.Canceled, false},
		{"context deadline exceeded", context.DeadlineExceeded, false},
		{"wrapped canceled", fmt.Errorf("storage: %w", context.Canceled), false},
		{"wrapped deadline exceeded", fmt.Errorf("storage: %w", context.DeadlineExceeded), false},
		{"genuine error", errors.New("disk failure"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{minLevel: slog.LevelInfo}
			logger := slog.New(Wrap(rec))
			logger.Error("failed to find output in Lookup", "outpoint", "abc:0", "error", c.err)
			if c.wantHandled {
				if len(rec.records) != 1 {
					t.Fatalf("got %d records, want 1 (a genuine error keeps its Error level and reaches the inner handler)", len(rec.records))
				}
				if rec.records[0].Level != slog.LevelError {
					t.Errorf("level = %v, want Error", rec.records[0].Level)
				}
			} else if len(rec.records) != 0 {
				t.Fatalf("got %d records, want 0 (downgraded to Debug, which the inner handler's Info floor drops)", len(rec.records))
			}
		})
	}
}

// TestWrap_PassesThroughAtDebugWhenInnerShowsIt: a downgraded record is not
// unconditionally swallowed — when the inner handler is itself configured
// to show Debug (someone turned on verbose logging), it still gets there,
// correctly labelled.
func TestWrap_PassesThroughAtDebugWhenInnerShowsIt(t *testing.T) {
	rec := &recorder{minLevel: slog.LevelDebug}
	logger := slog.New(Wrap(rec))
	logger.Error("failed to find output in Lookup", "outpoint", "abc:0", "error", context.Canceled)
	if len(rec.records) != 1 {
		t.Fatalf("got %d records, want 1 (inner shows Debug, so the downgraded record should reach it)", len(rec.records))
	}
	if rec.records[0].Level != slog.LevelDebug {
		t.Errorf("level = %v, want Debug", rec.records[0].Level)
	}
}

// TestWrap_NoErrorAttrKeepsItsLevel: a record with nothing under "error"
// cannot be classified as a cancellation, so it is left exactly alone.
func TestWrap_NoErrorAttrKeepsItsLevel(t *testing.T) {
	rec := &recorder{minLevel: slog.LevelInfo}
	logger := slog.New(Wrap(rec))
	logger.Error("something else entirely", "foo", "bar")
	if len(rec.records) != 1 || rec.records[0].Level != slog.LevelError {
		t.Fatalf("got %d records (want exactly 1, at Error)", len(rec.records))
	}
}

// TestWrap_NonErrorLevelsUnaffected: the downgrade only ever applies to a
// record already at Error — Warn, Info and Debug pass through untouched
// even when they happen to carry a context-cancellation "error" value.
func TestWrap_NonErrorLevelsUnaffected(t *testing.T) {
	rec := &recorder{minLevel: slog.LevelInfo}
	logger := slog.New(Wrap(rec))
	logger.Warn("something at warn", "error", context.Canceled)
	if len(rec.records) != 1 || rec.records[0].Level != slog.LevelWarn {
		t.Fatalf("got %d records (want exactly 1, at Warn, unaffected)", len(rec.records))
	}
}

// TestWrap_WithAttrsAndWithGroupStillWrap: a handler slog derives via
// WithAttrs or WithGroup (every *slog.Logger built with With(...) or
// WithGroup(...) does this) must still carry the downgrade behavior, not
// just the handler returned by Wrap itself.
func TestWrap_WithAttrsAndWithGroupStillWrap(t *testing.T) {
	rec := &recorder{minLevel: slog.LevelInfo}
	h := Wrap(rec).WithAttrs([]slog.Attr{slog.String("component", "test")}).WithGroup("g")
	logger := slog.New(h)
	logger.Error("failed to find output in Lookup", "error", context.Canceled)
	if len(rec.records) != 0 {
		t.Fatalf("got %d records, want 0: a handler derived via WithAttrs/WithGroup must still downgrade and drop", len(rec.records))
	}
}

// TestInstall_SetsAndRestoresTheDefault confirms Install both wraps and
// installs the current default, and that the installed logger behaves the
// same way Wrap's own handler does, end to end through slog.Default().
func TestInstall_SetsAndRestoresTheDefault(t *testing.T) {
	rec := &recorder{minLevel: slog.LevelInfo}
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(rec))

	got := Install()
	if got != slog.Default() {
		t.Fatalf("Install's return value is not what slog.Default() now returns")
	}
	slog.Default().Error("failed to find output in Lookup", "outpoint", "abc:0", "error", context.Canceled)
	if len(rec.records) != 0 {
		t.Fatalf("got %d records on the installed default, want 0 (cancellation downgraded and dropped)", len(rec.records))
	}
	slog.Default().Error("a genuine storage failure", "error", errors.New("disk failure"))
	if len(rec.records) != 1 || rec.records[0].Level != slog.LevelError {
		t.Fatalf("got %d records for a genuine error on the installed default, want 1 at Error", len(rec.records))
	}
}
