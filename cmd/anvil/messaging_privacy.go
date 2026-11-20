package main

// Decisions 2-5 (B6 messaging-privacy spec): wiring that turns the
// loaded config and the already-constructed v3 overlay engine into the
// HomeResolver + forward-copy-TTL + forward-peer-filter +
// operator-box-switch values internal/api and internal/gossip consume.
// Lives in its own file, same reason federation_loops.go does for
// wireV3Federation: so main.go's call sites stay a one-line call each
// instead of growing with this logic inline.

import (
	"github.com/BSVanon/Anvil/internal/config"
	anvilgossip "github.com/BSVanon/Anvil/internal/gossip"
	anvilmsg "github.com/BSVanon/Anvil/internal/messaging"
	"github.com/BSVanon/Anvil/internal/overlay/lookups"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// wireMessagingPrivacy builds the HomeResolver and hands back the two
// already-normalised config pointers (config.Load's normalizeMessagingPrivacy
// guarantees both are non-nil) that internal/api's ServerConfig needs
// verbatim. All three are computed unconditionally — independent of
// whether mesh/gossip is enabled — because the Home rule and the
// operator-box switch govern the REST API's /sendMessage,
// /listMessages, /acknowledgeMessage and /messages/subscribe paths on a
// node with no mesh peers at all, same as one with a full mesh. Call
// wireGossipMessagingPolicy separately, once gossipMgr exists, to apply
// the gossip-side half (decisions 3/4's forward scoping) using the same
// HomeResolver and TTL returned here, so both layers agree on who is
// Home.
func wireMessagingPrivacy(cfg *config.Config, v3Eng *engine.Engine) (home anvilmsg.HomeResolver, forwardCopyTTLSeconds *int64, operatorReadsAllBoxes *bool) {
	ownHosts := make([]string, 0, 1+len(cfg.Messaging.HomeHosts))
	if cfg.Node.PublicURL != "" {
		ownHosts = append(ownHosts, cfg.Node.PublicURL)
	}
	ownHosts = append(ownHosts, cfg.Messaging.HomeHosts...)
	home = anvilmsg.NewHomeResolver(ownHosts, messageBoxAdvertSource(v3Eng))
	return home, cfg.Messaging.ForwardCopyTTLSeconds, cfg.Messaging.OperatorReadsAllBoxes
}

// wireGossipMessagingPolicy applies decisions 3/4 to gossipMgr: the
// HomeResolver and forward_copy_ttl wireMessagingPrivacy already built
// for the API layer, plus the gossip-only forward_peers scoping. A nil
// gossipMgr (mesh disabled) is a no-op.
func wireGossipMessagingPolicy(gossipMgr *anvilgossip.Manager, cfg *config.Config, home anvilmsg.HomeResolver, forwardCopyTTLSeconds *int64) {
	if gossipMgr == nil {
		return
	}
	gossipMgr.SetMessagingPolicy(anvilgossip.MessagingPolicy{
		Home:                  home,
		ForwardCopyTTLSeconds: forwardCopyTTLSeconds,
		ForwardPeers:          anvilgossip.NewForwardPeerFilter(cfg.Messaging.ForwardPeers),
	})
}

// messageBoxAdvertSource adapts the v3 engine's already-registered
// ls_messagebox lookup service (internal/overlay/lookups/messagebox.go)
// to messaging.AdvertSource via its native CurrentHosts side-channel,
// reusing the single registered instance — engine.Engine.GetLookupService
// is the canonical thread-safe accessor — rather than opening a second
// lookup service against the same LevelDB handle. Returns nil when
// overlay is disabled (v3Eng == nil) or tm_messagebox/ls_messagebox
// isn't registered, which makes every Resolve answer Unadvertised
// (messaging.AdvertSource's documented nil behaviour) — the correct
// answer for "this node doesn't host the topic" (decision 2).
func messageBoxAdvertSource(v3Eng *engine.Engine) anvilmsg.AdvertSource {
	if v3Eng == nil {
		return nil
	}
	svc, ok := v3Eng.GetLookupService(topics.MessageBoxLookupServiceName)
	if !ok {
		return nil
	}
	mb, ok := svc.(*lookups.MessageBoxLookupService)
	if !ok {
		return nil
	}
	return func(identityKeyHex string) ([]anvilmsg.Advert, error) {
		hosts, err := mb.CurrentHosts(identityKeyHex)
		if err != nil {
			return nil, err
		}
		adverts := make([]anvilmsg.Advert, len(hosts))
		for i, h := range hosts {
			adverts[i] = anvilmsg.Advert{Host: h}
		}
		return adverts, nil
	}
}
