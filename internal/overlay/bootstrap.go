package overlay

import (
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/BSVanon/Anvil/pkg/brc"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Bootstrap registers the node's own SHIP tokens in the local directory
// for each configured topic. This is a local dev/operator convenience —
// not canonical overlay discovery. Real discovery comes from JungleBus
// or overlay lookup.
func Bootstrap(
	dir *Directory,
	identityKey *ec.PrivateKey,
	domain string,
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
