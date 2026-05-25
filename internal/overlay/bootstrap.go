package overlay

import (
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/BSVanon/Anvil/pkg/brc"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Bootstrap registers the node's own SHIP tokens in the local
// Anvil-Mesh peer directory for each configured topic. This populates
// the local directory entries that the /overlay/lookup HTTP API and
// gossip-mesh handlers query so other anvil-mesh nodes (anvil-a ↔
// anvil-b) can discover us via the bespoke peer-coordination layer.
//
// Anvil-Mesh internal discovery vs canonical BRC-88: these are TWO
// different systems. Bootstrap belongs to Anvil-Mesh — the bespoke
// internal coordination layer Anvil uses to find its own mesh peers,
// share topic state via gossip, and slash misbehaving identities.
// Canonical BRC-88 federation (the federation.Advertiser path) is for
// the wider BSV ecosystem — BRC-100 wallets and external overlay
// nodes finding Anvil via SHIP/SLAP trackers. Per the Codex 14a2d703
// scope carve-out (reference_anvil_teranode_boundary.md), the
// Anvil-Mesh layer stays forever.
func Bootstrap(
	dir *Directory,
	identityKey *ec.PrivateKey,
	domain string,
	nodeName string,
	version string,
	topics []string,
	logger *slog.Logger,
) error {
	identityPubHex := hex.EncodeToString(identityKey.PubKey().Compressed())

	for _, topic := range topics {
		scriptBytes, _, err := brc.BuildSHIPScript(identityKey, domain, topic)
		if err != nil {
			logger.Error("failed to build SHIP script", "topic", topic, "error", err)
			continue
		}

		entry := &PeerEntry{
			IdentityPub:  identityPubHex,
			Domain:       domain,
			NodeName:     nodeName,
			Version:      version,
			Topic:        topic,
			TxID:         "self-registered",
			OutputIndex:  0,
			DiscoveredAt: time.Now(),
		}

		if err := dir.AddSHIPPeer(entry, scriptBytes); err != nil {
			logger.Error("failed to register SHIP", "topic", topic, "error", err)
			continue
		}

		logger.Info("overlay: self-registered SHIP",
			"topic", topic,
			"domain", domain,
			"identity", identityPubHex[:16],
		)
	}

	return nil
}
