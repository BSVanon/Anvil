// Package enginelog quiets one specific, high-volume class of log record
// the overlay engine (github.com/bsv-blockchain/go-overlay-services) emits
// at Error: a storage lookup whose context was cancelled or timed out. The
// engine logs these itself, at its own call sites, using log/slog's
// package-level functions — there is no logger field on its Engine type to
// configure instead — so the only way to change how one of its messages is
// handled is to install the handler every slog call in the process ends up
// at.
package enginelog

import (
	"context"
	"errors"
	"log/slog"
)

// Wrap returns inner with one change: an Error record whose "error"
// attribute is, or wraps, context.Canceled or context.DeadlineExceeded is
// downgraded to Debug before inner sees it, and dropped entirely when
// inner would not show a Debug record anyway (the default, with no
// verbose logging turned on). Every other record passes through exactly
// as inner would have handled it, at its original level.
//
// This exists because a client that simply disconnects, or whose request
// context Anvil itself cancels at a deadline, reaches the engine's storage
// calls as a cancelled or expired context — ordinary and entirely the
// client's own choice, not a storage fault — and the engine logs that at
// Error on every occurrence it sees (go-overlay-services v1.3.1,
// engine.go:766, :846, :1233 and :1261: "failed to find output in
// Lookup", "... in GetUTXOHistory", "... for topic in
// ProvideForeignSyncResponse", "... in ProvideForeignGASPNode"). Nothing
// before this package rate-limits or classifies it, and nothing about the
// overlay routes that reach these calls does either, so any client that
// opens a lookup and disconnects before it answers can make the process
// log an Error line. A genuine storage failure carries a different error
// value and keeps its Error level and is unaffected.
func Wrap(inner slog.Handler) slog.Handler {
	return &quietCancel{inner: inner}
}

// Install wraps the process's current default slog handler with Wrap and
// installs the result as the new default (slog.SetDefault), then returns
// it. Every logger anything in the process gets from slog.Default() from
// this point on, including go-overlay-services' own package-level calls,
// sees the wrapped behavior. Called once, early in main, before the
// overlay engine or anything that might log through it is built.
func Install() *slog.Logger {
	slog.SetDefault(slog.New(Wrap(slog.Default().Handler())))
	return slog.Default()
}

type quietCancel struct {
	inner slog.Handler
}

func (h *quietCancel) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *quietCancel) Handle(ctx context.Context, r slog.Record) error {
	if r.Level == slog.LevelError && isCancellation(r) {
		r.Level = slog.LevelDebug
		if !h.inner.Enabled(ctx, slog.LevelDebug) {
			return nil // the inner handler's own level would drop this anyway
		}
	}
	return h.inner.Handle(ctx, r)
}

func (h *quietCancel) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &quietCancel{inner: h.inner.WithAttrs(attrs)}
}

func (h *quietCancel) WithGroup(name string) slog.Handler {
	return &quietCancel{inner: h.inner.WithGroup(name)}
}

// isCancellation reports whether r carries an "error" attribute holding an
// error that is, or wraps, context.Canceled or context.DeadlineExceeded.
// Every cited call site logs its error under this exact key.
func isCancellation(r slog.Record) bool {
	found := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key != "error" {
			return true // keep looking
		}
		err, ok := a.Value.Any().(error)
		found = ok && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))
		return false // "error" found (matching or not): stop
	})
	return found
}
