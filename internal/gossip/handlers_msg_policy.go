package gossip

// Decision 3 and 4 (B6 messaging-privacy spec): the gossip-side store/
// relay policy for an incoming forward, and the forward_peers seam.
//
// deliverForward applies decision 3's "Forward received" table rows:
//
//	| The recipient is          | Store?                  | TTL              | Relay?                                   |
//	|----------------------------|--------------------------|-------------------|-------------------------------------------|
//	| Home                       | yes                      | ttl_seconds       | only if it also advertises another host  |
//	| Unadvertised or Elsewhere  | if forward_copy_ttl > 0  | forward_copy_ttl  | always                                    |
//
// Either way, a relay of a message this node did NOT just store goes
// through the manager-wide allowUnstoredRelay budget (relay_budget.go) on
// top of the per-peer gossip bucket already checked at entry
// (allowPeerMessage, manager_seed.go) — decision 3's "relay bound". A
// relay of a message this node DID just store is unconditional, exactly
// as it already was before this policy existed; storing it is itself the
// bound (the quota layer), so no second budget applies.

import (
	"errors"
	"strings"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// ForwardPeerFilter decides whether a connected peer may receive message
// forwards and relays (decision 4's [messaging] forward_peers key). A nil
// filter means every connected peer, today's behaviour. It is a plain
// predicate rather than a struct, deliberately: the seam B10 extends to
// certified peers.
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

// MessagingPolicy bundles decision 2/3/4's gossip-side configuration.
//
// ForwardCopyTTLSeconds is a pointer for the same reason the config
// layer uses one (internal/config): nil must mean something different
// from an explicit zero. Decision 3 gives operators a real, meaningful
// zero ("0 means copies on non-home nodes are relayed but never
// stored"), so a bare int64 could not tell that apart from "nobody
// called SetMessagingPolicy at all." cmd/anvil always wires a concrete,
// already-defaulted value (nil config -> 86400) — it is only ever nil
// here when messaging privacy was never wired up at all, e.g. a Manager
// built directly in a test. That case, and ForwardPeers nil, and Home
// nil, all reproduce the exact pre-decision-3/4 behaviour: see
// deliverForward and peerAllowedForForward.
type MessagingPolicy struct {
	Home                  messaging.HomeResolver
	ForwardCopyTTLSeconds *int64
	ForwardPeers          ForwardPeerFilter
}

// SetMessagingPolicy wires decision 2/3/4's policy into the manager.
// Mirrors SetMsgStore: called once during startup wiring, before the
// manager handles concurrent traffic, so it takes no lock.
func (m *Manager) SetMessagingPolicy(p MessagingPolicy) {
	m.messagingPolicy = p
}

func (m *Manager) homeResolverOrDefault() messaging.HomeResolver {
	if m.messagingPolicy.Home != nil {
		return m.messagingPolicy.Home
	}
	return messaging.AlwaysUnadvertised
}

// peerAllowedForForward reports whether peerKey may receive a message
// forward or relay (decision 4). Always true when forward_peers is unset.
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

// deliverForward decides and performs the store, per decision 3's table,
// for an incoming forward addressed to msg.Recipient, attested by
// attestedBy. The caller (onMsgForward, handlers_msg.go) must already
// have confirmed m.msgStore != nil.
//
// ForwardCopyTTLSeconds nil means decisions 2/3 were never wired up at
// all (see MessagingPolicy's doc comment) — deliverLegacyForward
// reproduces the exact pre-brick behaviour for that case, without
// consulting the Home resolver at all (today's code had no such
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

// deliverLegacyForward is the pre-decision-3 contract: store
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

// deliverHomeForward is decision 3's "Forward received, Home" row: store
// at ttl_seconds via the unchanged Deliver, relay only when the recipient
// also advertises a host that isn't this node.
func (m *Manager) deliverHomeForward(msg *messaging.Message, attestedBy string, hasOtherHost bool) forwardDeliveryOutcome {
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
		m.logger.Debug("forwarded message delivered (home)", "id", msg.MessageID, "recipient", msg.Recipient)
	}
	return forwardDeliveryOutcome{relay: hasOtherHost}
}

// deliverNonHomeForward is decision 3's "Forward received, Unadvertised
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
	return forwardDeliveryOutcome{relay: true}
}

func isQuotaErr(err error) bool {
	return errors.Is(err, messaging.ErrPairQuota) ||
		errors.Is(err, messaging.ErrInboxQuota) ||
		errors.Is(err, messaging.ErrStoreFull)
}
