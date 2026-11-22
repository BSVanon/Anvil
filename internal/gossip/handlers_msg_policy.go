package gossip

// The gossip-side store/relay policy for an incoming forward, and the
// forward_peers seam.
//
// deliverForward applies the "Forward received" table rows below:
//
//	| The recipient is          | Store?                  | TTL              | Relay?                                   |
//	|----------------------------|--------------------------|-------------------|-------------------------------------------|
//	| Home                       | yes                      | ttl_seconds       | only if it also advertises another host  |
//	| Unadvertised or Elsewhere  | if forward_copy_ttl > 0  | forward_copy_ttl  | only if the store call succeeded         |
//
// Either way, a relay of a message this node did NOT just store goes
// through the manager-wide allowUnstoredRelay budget (relay_budget.go) on
// top of the per-peer gossip bucket already checked at entry
// (allowPeerMessage, manager_seed.go) — this table's own "relay bound". A
// relay of a message this node DID just store is unconditional, exactly
// as it already was before this policy existed; storing it is itself the
// bound (the quota layer), so no second budget applies.

import (
	"errors"
	"strings"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// ForwardPeerFilter decides whether a connected peer may receive message
// forwards and relays, from the [messaging] forward_peers key. A nil
// filter means every connected peer, today's behaviour. It is a plain
// predicate rather than a struct, deliberately: the same seam a future
// certified-peers extension can build on.
type ForwardPeerFilter func(peerKey string) bool

// NewForwardPeerFilter builds a ForwardPeerFilter from the configured
// [messaging] forward_peers hex identity keys. Blank entries are ignored;
// comparisons are case-insensitive, mirroring newPeerAllowlist's
// convention (allowlist.go). An empty list returns nil — "every connected
// peer, as today" — so callers can use a simple nil check instead of
// tracking an separate "enabled" flag.
func NewForwardPeerFilter(hexKeys []string) ForwardPeerFilter {
	set := make(map[string]struct{}, len(hexKeys))
	for _, k := range hexKeys {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		set[k] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return func(peerKey string) bool {
		_, ok := set[strings.ToLower(peerKey)]
		return ok
	}
}

// MessagingPolicy bundles the Home Rule, forward-copy-TTL and
// forward_peers gossip-side configuration.
//
// ForwardCopyTTLSeconds is a pointer for the same reason the config
// layer uses one (internal/config): nil must mean something different
// from an explicit zero. forward_copy_ttl has a real, meaningful
// zero ("0 means copies on non-home nodes are relayed but never
// stored"), so a bare int64 could not tell that apart from "nobody
// called SetMessagingPolicy at all." cmd/anvil always wires a concrete,
// already-defaulted value (nil config -> 86400) — it is only ever nil
// here when messaging privacy was never wired up at all, e.g. a Manager
// built directly in a test. That case, and ForwardPeers nil, and Home
// nil, all reproduce the exact original (no policy) behaviour: see
// deliverForward and peerAllowedForForward.
type MessagingPolicy struct {
	Home                  messaging.HomeResolver
	ForwardCopyTTLSeconds *int64
	ForwardPeers          ForwardPeerFilter
	PrivateHomes          *messaging.PrivateHomeStore
}

// SetMessagingPolicy wires the Home/forward/forward_peers policy into the manager.
// Production calls it before mesh startup. ResyncPrivateHomes also repairs a
// missed announcement if a caller installs it after a peer was admitted.
func (m *Manager) SetMessagingPolicy(p MessagingPolicy) {
	if m.messagingPolicy.PrivateHomes != nil && m.messagingPolicy.PrivateHomes != p.PrivateHomes {
		m.messagingPolicy.PrivateHomes.SetOnRecordChanged(nil)
	}
	m.messagingPolicy = p
	if p.PrivateHomes != nil {
		p.PrivateHomes.SetOnRecordChanged(m.onPrivateHomeRecordChanged)
	}
	m.ResyncPrivateHomes()
}

func (m *Manager) homeResolverOrDefault() messaging.HomeResolver {
	if m.messagingPolicy.Home != nil {
		return m.messagingPolicy.Home
	}
	return messaging.AlwaysUnadvertised
}

// peerAllowedForForward reports whether peerKey may receive a message
// forward or relay. Always true when forward_peers is unset.
func (m *Manager) peerAllowedForForward(peerKey string) bool {
	filter := m.messagingPolicy.ForwardPeers
	return filter == nil || filter(peerKey)
}

// forwardDeliveryOutcome is deliverForward's answer for one incoming
// forward: whether onMsgForward should relay it, and whether the dedup
// entry must be cleared so a later legitimate retry isn't suppressed by
// this (failed, non-quota) attempt.
type forwardDeliveryOutcome struct {
	relay     bool
	clearSeen bool
}

// deliverForward decides and performs the store, per the table above,
// for an incoming forward addressed to msg.Recipient, attested by
// attestedBy. The caller (onMsgForward, handlers_msg.go) must already
// have confirmed m.msgStore != nil.
//
// ForwardCopyTTLSeconds nil means the Home/forward policy was never
// wired up at all (see MessagingPolicy's doc comment) — deliverLegacyForward
// reproduces the exact original behaviour for that case, without
// consulting the Home resolver at all (the original code had no such
// concept).
func (m *Manager) deliverForward(msg *messaging.Message, attestedBy string) forwardDeliveryOutcome {
	if m.messagingPolicy.ForwardCopyTTLSeconds == nil {
		return m.deliverLegacyForward(msg, attestedBy)
	}
	res, err := m.homeResolverOrDefault().Resolve(msg.Recipient)
	if err != nil {
		m.logger.Debug("home resolution failed, treating recipient as unadvertised", "error", err)
		res = messaging.Resolution{State: messaging.Unadvertised}
	}
	if res.State == messaging.Home {
		return m.deliverHomeForward(msg, attestedBy, res.HasOtherHost)
	}
	return m.deliverNonHomeForward(msg, attestedBy, *m.messagingPolicy.ForwardCopyTTLSeconds)
}

// deliverLegacyForward is the original (no Home-policy) contract: store
// unconditionally via Deliver (ttl_seconds) and relay unconditionally on
// success, falling back to the bounded relay on a quota rejection. Only
// reachable when messaging privacy was never wired (see deliverForward).
func (m *Manager) deliverLegacyForward(msg *messaging.Message, attestedBy string) forwardDeliveryOutcome {
	ok, err := m.msgStore.Deliver(msg, attestedBy)
	if err != nil {
		if isQuotaErr(err) {
			m.logMessageQuotaDrop(err)
			return forwardDeliveryOutcome{relay: m.allowUnstoredRelay()}
		}
		m.logger.Debug("forwarded message store failed", "error", err)
		return forwardDeliveryOutcome{clearSeen: true}
	}
	if ok {
		m.logger.Debug("forwarded message delivered", "id", msg.MessageID, "recipient", msg.Recipient)
	}
	return forwardDeliveryOutcome{relay: ok}
}

// deliverHomeForward is the "Forward received, Home" row: store
// at ttl_seconds via the unchanged Deliver, relay only when the recipient
// also advertises a host that isn't this node.
//
// Two bugs fixed here. Both outcomes below used to relay
// without checking ok (whether the store call actually inserted a new
// record) first:
//   - the quota-rejection branch relayed through allowUnstoredRelay
//     whenever the store was full, even when hasOtherHost was false —
//     spreading a Home-only message to non-home nodes with no delivery
//     reason, every time this node's inbox/pair/store quota was hit.
//   - the success branch relayed on hasOtherHost alone, regardless
//     of ok. Deliver returns (false, nil) for a message already stored
//     (e.g. this node's own forward echoing back in a cyclic mesh, or a
//     msgSeen dedup eviction), so a duplicate forward was relayed again
//     on every such retry — unbounded, and bypassing allowUnstoredRelay
//     entirely, contradicting this file's own header and the relay
//     bound above.
func (m *Manager) deliverHomeForward(msg *messaging.Message, attestedBy string, hasOtherHost bool) forwardDeliveryOutcome {
	ok, err := m.msgStore.Deliver(msg, attestedBy)
	if err != nil {
		if isQuotaErr(err) {
			m.logMessageQuotaDrop(err)
			return forwardDeliveryOutcome{relay: hasOtherHost && m.allowUnstoredRelay()}
		}
		m.logger.Debug("forwarded message store failed", "error", err)
		return forwardDeliveryOutcome{clearSeen: true}
	}
	if ok {
		m.logger.Debug("forwarded message delivered (home)", "id", msg.MessageID, "recipient", msg.Recipient)
	}
	return forwardDeliveryOutcome{relay: ok && hasOtherHost}
}

// deliverNonHomeForward is the "Forward received, Unadvertised
// or Elsewhere" row: store a forward_copy_ttl-bounded copy when
// forward_copy_ttl > 0 (DeliverCopy), store nothing when it is 0, and
// relay either way — bounded by allowUnstoredRelay whenever this node
// holds no local copy to fall back on. ttl is the caller's already
// resolved (non-nil) forward_copy_ttl.
func (m *Manager) deliverNonHomeForward(msg *messaging.Message, attestedBy string, ttl int64) forwardDeliveryOutcome {
	if ttl <= 0 {
		return forwardDeliveryOutcome{relay: m.allowUnstoredRelay()}
	}
	ok, err := m.msgStore.DeliverCopy(msg, attestedBy, ttl)
	if err != nil {
		if isQuotaErr(err) {
			m.logMessageQuotaDrop(err)
			return forwardDeliveryOutcome{relay: m.allowUnstoredRelay()}
		}
		m.logger.Debug("forwarded message store failed", "error", err)
		return forwardDeliveryOutcome{clearSeen: true}
	}
	if ok {
		m.logger.Debug("forwarded message delivered (copy)", "id", msg.MessageID, "recipient", msg.Recipient)
	}
	return forwardDeliveryOutcome{relay: ok}
}

func isQuotaErr(err error) bool {
	return errors.Is(err, messaging.ErrPairQuota) ||
		errors.Is(err, messaging.ErrInboxQuota) ||
		errors.Is(err, messaging.ErrStoreFull)
}
