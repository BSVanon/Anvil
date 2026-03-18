package overlay

import (
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/BSVanon/Anvil/pkg/brc"
)

// Discoverer queries the overlay directory for mesh peers and processes
// incoming SHIP/SLAP token scripts from on-chain sources (JungleBus, etc.).
type Discoverer struct {
	dir    *Directory
	logger *slog.Logger
}

// NewDiscoverer creates a new overlay discoverer.
func NewDiscoverer(dir *Directory, logger *slog.Logger) *Discoverer {
	return &Discoverer{dir: dir, logger: logger}
}

// ProcessSHIPScript parses and validates a SHIP token script found on-chain,
// then adds it to the directory. Called by JungleBus subscriber or manual scan.
func (d *Discoverer) ProcessSHIPScript(script []byte, txid string, outputIndex int) error {
	token, err := brc.ValidateSHIPToken(script)
	if err != nil {
		return err
	}

	entry := &PeerEntry{
		IdentityPub:  token.IdentityPub,
		Domain:       token.Domain,
		Topic:        token.Topic,
		TxID:         txid,
		OutputIndex:  outputIndex,
		DiscoveredAt: time.Now(),
	}

	if err := d.dir.AddSHIPPeer(entry, script); err != nil {
		return err
	}

	d.logger.Info("discovered SHIP peer",
		"identity", token.IdentityPub[:16],
		"domain", token.Domain,
		"topic", token.Topic,
		"txid", txid,
	)
	return nil
}

// ProcessSLAPScript parses and validates a SLAP token script found on-chain.
func (d *Discoverer) ProcessSLAPScript(script []byte, txid string, outputIndex int) error {
	token, err := brc.ValidateSLAPToken(script)
	if err != nil {
		return err
	}

	entry := &ProviderEntry{
		IdentityPub:  token.IdentityPub,
		Domain:       token.Domain,
		Provider:     token.Provider,
		TxID:         txid,
		OutputIndex:  outputIndex,
		DiscoveredAt: time.Now(),
	}

	if err := d.dir.AddSLAPProvider(entry, script); err != nil {
		return err
	}

	d.logger.Info("discovered SLAP provider",
		"identity", token.IdentityPub[:16],
		"domain", token.Domain,
		"provider", token.Provider,
		"txid", txid,
	)
	return nil
}

// DiscoverPeersForTopic returns known SHIP peers for a topic.
func (d *Discoverer) DiscoverPeersForTopic(topic string) ([]*PeerEntry, error) {
	return d.dir.LookupSHIPByTopic(topic)
}

// Suppress unused import
var _ = hex.EncodeToString
