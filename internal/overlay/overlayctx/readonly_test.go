package overlayctx

import (
	"context"
	"testing"
)

// TestReadOnly_MarksAndKeepsTheContext: a marked context reports the mark,
// keeps the caller's cancellation and values, and passes the mark to the
// contexts derived from it, the engine's own among them; an unmarked one, and
// one whose cancellation context.WithoutCancel removed, report as they were.
func TestReadOnly_MarksAndKeepsTheContext(t *testing.T) {
	type key struct{}
	base, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "carried"))
	if IsReadOnly(base) {
		t.Fatal("an unmarked context reports read-only")
	}
	ctx := ReadOnly(base)
	derived, stop := context.WithCancel(ctx)
	defer stop()
	cancel()
	switch {
	case !IsReadOnly(ctx) || !IsReadOnly(derived):
		t.Fatal("a marked context, or one derived from it, does not report read-only")
	case ctx.Err() == nil || derived.Err() == nil:
		t.Fatal("the mark dropped the caller's cancellation")
	case ctx.Value(key{}) != "carried":
		t.Fatal("the mark dropped the caller's values")
	case !IsReadOnly(context.WithoutCancel(ctx)):
		t.Fatal("WithoutCancel dropped the mark, a value")
	}
}
