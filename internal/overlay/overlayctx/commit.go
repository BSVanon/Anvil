// Package overlayctx carries request-scoped signals through the canonical
// overlay engine, which passes the submit context opaquely from the HTTP
// handler down to the storage layer.
//
// Its one job today: let the legacy /overlay/submit handler learn the exact
// moment EACH submitted topic's transaction becomes *durably committed* (and
// therefore discoverable on this node). The engine commits topics one at a time
// (commitAdmittedOutputs loops Topics), so a single submit produces one signal
// per topic:
//
//   - a freshly-admitted topic signals after the engine's final
//     Storage.InsertAppliedTransaction for that topic (outputs persisted+indexed);
//   - a duplicate topic (this tx was already applied to it in a prior submit)
//     signals at Storage.DoesAppliedTransactionExist — it is already durable.
//
// The handler registers a notifier and acks success only once EVERY submitted
// topic has signaled, so a 200 always means the whole submit is durably
// committed — never a partial commit. Best-effort cross-node propagation (which
// the go-sdk topic facilitator runs on its own un-cancellable ~30s-per-peer
// timeout) then finishes in the background. The engine in between is a
// transparent pass-through; non-submit callers (GASP sync, internalize) register
// no notifier and the signals are no-ops.
package overlayctx

import "context"

type topicCommitKey struct{}

// WithTopicCommitNotifier returns a context carrying notify, invoked by the
// storage layer with the topic name each time a submitted tx is durably applied
// for that topic (newly committed, or already-present from a prior submit). A
// nil notify returns ctx unchanged.
func WithTopicCommitNotifier(ctx context.Context, notify func(topic string)) context.Context {
	if notify == nil {
		return ctx
	}
	return context.WithValue(ctx, topicCommitKey{}, notify)
}

// NotifyTopicCommitted invokes the topic-commit notifier carried by ctx, if any.
// Safe to call unconditionally — a no-op when no notifier is present (the normal
// case for GASP sync, internalize, and other non-legacy-submit code paths).
func NotifyTopicCommitted(ctx context.Context, topic string) {
	if notify, ok := ctx.Value(topicCommitKey{}).(func(string)); ok && notify != nil {
		notify(topic)
	}
}
