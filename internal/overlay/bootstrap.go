package overlay

import (
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/BSVanon/Anvil/pkg/brc"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Bootstrap registers the node's own SHIP tokens in the local directory
// for each configured topic. This makes the node discoverable to peers
// who query the overlay.
//
// This is the startup population path — the node advertises itself.
// On-chain publication of the SHIP token is a separate step (requires
// a funded wallet transaction). This only populates the local directory.
func Bootstrap(
	dir *Directory,
	identityKey *secp256k1.PrivateKey,
	domain string,
	topics []string,
	logger *slog.Logger,
) error {
	identityPubHex := hex.EncodeToString(identityKey.PubKey().SerializeCompressed())

	for _, topic := range topics {
		script, _, err := brc.BuildSHIPScript(identityKey, domain, topic)
		if err != nil {
			logger.Error("failed to build SHIP script", "topic", topic, "error", err)
			continue
		}

		entry := &PeerEntry{
			IdentityPub:  identityPubHex,
			Domain:       domain,
			Topic:        topic,
			TxID:         "self-registered",
			OutputIndex:  0,
			DiscoveredAt: time.Now(),
		}

		if err := dir.AddSHIPPeer(entry, script); err != nil {
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
