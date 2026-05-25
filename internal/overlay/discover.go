package overlay

import (
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/BSVanon/Anvil/pkg/brc"
)

// Discoverer queries the Anvil-Mesh peer directory and processes
// inbound SHIP token scripts received via the /overlay/register HTTP
// endpoint. Anvil-Mesh internal peer-coordination layer, NOT canonical
// BRC-88 federation — canonical SHIP/SLAP discovery is handled
// upstream by the v3 engine's LookupResolver via DEFAULT_SLAP_TRACKERS.
//
// As of v3.0.0 (W-10.5), the only caller of ProcessSHIPScript is
// internal/api/handlers.go's handleOverlayRegister, which forwards
// SHIP scripts other anvil-mesh nodes submit to us via the bespoke
// /overlay/register API. Pre-v3, this was also invoked by a JungleBus
// subscription loop; that path is retired.
type Discoverer struct {
	dir    *Directory
	logger *slog.Logger
}

// NewDiscoverer creates a new Anvil-Mesh peer discoverer.
func NewDiscoverer(dir *Directory, logger *slog.Logger) *Discoverer {
	return &Discoverer{dir: dir, logger: logger}
}

// ProcessSHIPScript parses and validates a SHIP token script another
// anvil-mesh node has submitted via /overlay/register, then adds it
// to the local peer directory so anvil-a learns anvil-b exists (and
// vice versa).
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
