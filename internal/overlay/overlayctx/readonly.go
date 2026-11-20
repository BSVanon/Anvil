package overlayctx

import "context"

type readOnlyKey struct{}

// ReadOnly marks ctx as the context of a request that only reads, a lookup or
// a GASP reply, so that the storage reads the engine makes for it stop once
// ctx ends, when its client goes away. The engine's view of storage
// (v3engine's detachedStorage) otherwise runs every call, reads included,
// without the caller's cancellation, because the engine reads between the
// writes of a commit; and it runs every write so whatever the mark.
func ReadOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, readOnlyKey{}, true)
}

// IsReadOnly reports whether ReadOnly marked ctx.
func IsReadOnly(ctx context.Context) bool {
	marked, _ := ctx.Value(readOnlyKey{}).(bool)
	return marked
}
