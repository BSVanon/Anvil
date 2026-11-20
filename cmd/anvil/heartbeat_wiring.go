package main

import "github.com/BSVanon/Anvil/internal/envelope"

// heartbeatTopicsFn returns the mesh-heartbeat TopicsFn wiring bound to a
// real envelope.Store. Pulled out of main() so a test can call it directly
// against a real store — not a stub — and confirm it resolves to the
// public-only accessor (envelope.Store.PublicTopics), never the unfiltered
// Store.Topics, without starting the whole node.
func heartbeatTopicsFn(envStore *envelope.Store) func() map[string]int {
	return envStore.PublicTopics
}

// heartbeatPrivateOnlyTopicsFn returns the mesh-heartbeat
// PrivateOnlyTopicsFn wiring bound to a real envelope.Store. Same rationale
// as heartbeatTopicsFn: lets a test exercise the real accessor
// (envelope.Store.PrivateOnlyTopics) instead of a stub.
func heartbeatPrivateOnlyTopicsFn(envStore *envelope.Store) func() map[string]struct{} {
	return envStore.PrivateOnlyTopics
}
