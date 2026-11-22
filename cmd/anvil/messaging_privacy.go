package main

// Wiring that turns the loaded config and the already-constructed v3
// overlay engine into the HomeResolver + forward-copy-TTL +
// forward-peer-filter + operator-box-switch values internal/api and
// internal/gossip consume.
// Lives in its own file, same reason federation_loops.go does for
// wireV3Federation: so main.go's call sites stay a one-line call each
// instead of growing with this logic inline.

import (
	"context"
	"encoding/hex"
	"log/slog"
	"time"

	anvilapi "github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/BSVanon/Anvil/internal/config"
	anvilgossip "github.com/BSVanon/Anvil/internal/gossip"
	anvilmsg "github.com/BSVanon/Anvil/internal/messaging"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/overlay/lookups"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// wireMessagingPrivacy builds the api.MessagingPolicy — one struct,
// not three separate values — that internal/api's ServerConfig needs
// verbatim: the HomeResolver plus the two already-normalised config
// pointers (config.Load's normalizeMessagingPrivacy guarantees both are
// non-nil). Computed unconditionally — independent of whether
// mesh/gossip is enabled — because the Home rule and the operator-box
// switch govern the REST API's /sendMessage, /listMessages,
// /acknowledgeMessage and /messages/subscribe paths on a node with no
// mesh peers at all, same as one with a full mesh. wireGossipMessagingPolicy
// calls this itself once gossipMgr/msgStore exist, so both layers agree
// on who is Home from the same computation.
//
// overlayDir is the same *anviloverlay.Directory main.go opens for the
// v3 engine's LookupDB (nil exactly when overlay is disabled, matching
// v3Eng == nil): messageBoxAdvertSource reads ls_messagebox's own
// LevelDB index directly through it. See that function's doc comment
// for why it does not go through v3Eng instead.
func wireMessagingPrivacy(cfg *config.Config, v3Eng *engine.Engine, overlayDir *anviloverlay.Directory) anvilapi.MessagingPolicy {
	ownHosts := make([]string, 0, 1+len(cfg.Messaging.HomeHosts))
	if cfg.Node.PublicURL != "" {
		ownHosts = append(ownHosts, cfg.Node.PublicURL)
	}
	ownHosts = append(ownHosts, cfg.Messaging.HomeHosts...)
	home := anvilmsg.NewHomeResolver(ownHosts, messageBoxAdvertSource(v3Eng, overlayDir))
	return anvilapi.MessagingPolicy{
		Home:                  home,
		ForwardCopyTTLSeconds: cfg.Messaging.ForwardCopyTTLSeconds,
		OperatorReadsAllBoxes: cfg.Messaging.OperatorReadsAllBoxes,
	}
}

// buildMessagingPolicy constructs the shared API/gossip policy without starting
// network work. Production reconciles durable certificate bindings, then calls
// applyGossipMessagingPolicy before starting seeds or the inbound listener.
func buildMessagingPolicy(cfg *config.Config, v3Eng *engine.Engine, overlayDir *anviloverlay.Directory, msgStore *anvilmsg.Store) anvilapi.MessagingPolicy {
	policy := wireMessagingPrivacy(cfg, v3Eng, overlayDir)
	var privateHomes *anvilmsg.PrivateHomeStore
	if cfg.Messaging.PrivateHomes && msgStore != nil {
		ownIdentity := ""
		if key, err := ec.PrivateKeyFromWif(cfg.Identity.WIF); err == nil {
			ownIdentity = hex.EncodeToString(key.PubKey().Compressed())
		}
		allowedHomes := append([]string(nil), cfg.Mesh.AllowedPeers...)
		if ownIdentity != "" {
			allowedHomes = append(allowedHomes, ownIdentity)
		}
		privateHomes = anvilmsg.NewPrivateHomeStore(msgStore, anvilmsg.PrivateHomeOptions{
			MaxMembers:   cfg.Messaging.PrivateHomeMaxMembers,
			MaxTTL:       cfg.Messaging.PrivateHomeMaxTTL,
			AllowedHomes: allowedHomes,
		})
		policy.PrivateHomes = privateHomes
		policy.Home = anvilmsg.NewPrivateHomeResolver(privateHomes, ownIdentity, policy.Home)
	}
	return policy
}

func buildStartupMessagingPolicy(cfg *config.Config, v3Eng *engine.Engine, overlayDir *anviloverlay.Directory, msgStore *anvilmsg.Store, gate *certgate.Gate, logger *slog.Logger) anvilapi.MessagingPolicy {
	policy := buildMessagingPolicy(cfg, v3Eng, overlayDir, msgStore)
	if policy.PrivateHomes != nil && gate != nil {
		gate.OnRevoke("private_homes", func(identity string) {
			if _, _, err := policy.PrivateHomes.RevokeMember(identity); err != nil && logger != nil {
				logger.Error("private home startup revocation failed", "error", err)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := anvilapi.ReconcilePrivateHomeAdmissions(ctx, policy.PrivateHomes, gate); err != nil {
		if logger != nil {
			logger.Error("private home admission reconciliation failed", "error", err)
		}
	}
	return policy
}

func applyGossipMessagingPolicy(gossipMgr *anvilgossip.Manager, cfg *config.Config, policy anvilapi.MessagingPolicy, msgStore *anvilmsg.Store) anvilapi.MessagingPolicy {
	if gossipMgr == nil {
		return policy
	}
	gossipMgr.SetMsgStore(msgStore)
	gossipMgr.SetMessagingPolicy(anvilgossip.MessagingPolicy{
		Home:                  policy.Home,
		ForwardCopyTTLSeconds: policy.ForwardCopyTTLSeconds,
		ForwardPeers:          anvilgossip.NewForwardPeerFilter(cfg.Messaging.ForwardPeers),
		PrivateHomes:          policy.PrivateHomes,
	})
	policy.PrivateHomeCompatible = gossipMgr.CanApplyPrivateHomeClaim
	return policy
}

func wireGossipMessagingPolicy(gossipMgr *anvilgossip.Manager, cfg *config.Config, v3Eng *engine.Engine, overlayDir *anviloverlay.Directory, msgStore *anvilmsg.Store) anvilapi.MessagingPolicy {
	return applyGossipMessagingPolicy(gossipMgr, cfg, buildMessagingPolicy(cfg, v3Eng, overlayDir, msgStore), msgStore)
}

// messageBoxAdvertSource adapts ls_messagebox's own LevelDB index
// (internal/overlay/lookups/messagebox.go) to messaging.AdvertSource.
//
// This used to fetch the v3 engine's registered lookup service via
// engine.Engine.GetLookupService and type-assert it to
// *lookups.MessageBoxLookupService. That assertion always failed:
// v3engine.New wraps every registered lookup service in an internal
// detachedLookup/countingLookup pair (internal/overlay/v3engine/engine.go)
// for health-registry notification bookkeeping, so GetLookupService
// never returns the concrete type a type-assertion could reach. The
// adapter therefore always returned nil, and the Home rule never ran in
// production — every recipient resolved Unadvertised regardless of its
// actual advert.
//
// Fix: build a second lookups.NewMessageBoxLookupService(overlayDir.DB())
// reader directly against the SAME shared overlay LevelDB handle main.go
// already opened for v3engine.Config.LookupDB, instead of reaching
// through the engine's wrapper. This is correct because the type holds
// no mutable state beyond the db handle itself and CurrentHosts only
// reads, and it is the smaller change: the alternative (adding an
// Unwrap() escape hatch to the v3engine wrapper types) would touch
// v3engine itself, which this change otherwise leaves alone.
//
// Still confirms v3Eng has the topic registered before building the
// reader, preserving the documented "nil when overlay is disabled or
// tm_messagebox/ls_messagebox isn't registered" contract — a disabled
// topic's LevelDB key family would just stay permanently empty, but
// checking explicitly keeps the nil-AdvertSource signal precise and
// avoids opening a reader that can never find anything.
func messageBoxAdvertSource(v3Eng *engine.Engine, overlayDir *anviloverlay.Directory) anvilmsg.AdvertSource {
	if v3Eng == nil || overlayDir == nil {
		return nil
	}
	if _, ok := v3Eng.GetLookupService(topics.MessageBoxLookupServiceName); !ok {
		return nil
	}
	mb := lookups.NewMessageBoxLookupService(overlayDir.DB())
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
