package config

import (
	"fmt"
	"net/url"
)

// MeshConfig defines Anvil mesh peering via go-sdk auth.Peer + WebSocket.
type MeshConfig struct {
	Seeds []string `toml:"seeds"` // WebSocket endpoints of seed peers
	// PeerExchange advertises and dials authenticated heartbeat peer records.
	PeerExchange     bool   `toml:"peer_exchange"`
	AdvertiseURL     string `toml:"advertise_url"`
	MaxExchangePeers int    `toml:"max_exchange_peers"`

	// AllowedPeers is a closed-network allowlist of identity public keys
	// (hex). Empty means today's behaviour: any peer that completes the
	// BRC-31 handshake may connect (MinBondSats rules still apply). When
	// set, an inbound or outbound peer whose authenticated identity isn't
	// listed is dropped immediately after the handshake, before any of
	// its messages are processed, for both AcceptPeer and
	// ConnectPeer/ConnectSeedWithReconnect.
	AllowedPeers []string `toml:"allowed_peers"`

	MinBondSats  int      `toml:"min_bond_sats"`  // minimum bond UTXO required to peer (0 = no bond required)
	BondCheckURL string   `toml:"bond_check_url"` // UTXO lookup API (default: WoC)
	LocalPubkeys []string `toml:"local_pubkeys"`  // app pubkeys exempt from double-publish slashing on this node
	RatePerSec   float64  `toml:"rate_per_sec"`   // per-peer envelope rate limit (default: 30)
	RateBurst    int      `toml:"rate_burst"`     // per-peer burst allowance (default: 100)
}

func defaultMeshConfig() MeshConfig {
	return MeshConfig{PeerExchange: true, MaxExchangePeers: 8}
}

func finalizeMeshConfig(mesh *MeshConfig, deprecated MeshConfig) error {
	// Merge deprecated [foundry] into [mesh] for backward compatibility.
	if len(deprecated.Seeds) > 0 && len(mesh.Seeds) == 0 {
		mesh.Seeds = deprecated.Seeds
	}
	if mesh.MaxExchangePeers < 0 || mesh.MaxExchangePeers > 64 {
		return fmt.Errorf("mesh.max_exchange_peers must be between 0 and 64")
	}
	if mesh.AdvertiseURL != "" {
		if err := validateMeshAdvertiseURL(mesh.AdvertiseURL); err != nil {
			return fmt.Errorf("mesh.advertise_url: %w", err)
		}
	}
	return nil
}

func validateMeshAdvertiseURL(raw string) error {
	if len(raw) > 512 {
		return fmt.Errorf("must be at most 512 bytes")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("scheme must be ws:// or wss://")
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("host is required")
	}
	if u.User != nil {
		return fmt.Errorf("userinfo is not allowed")
	}
	if u.RawQuery != "" {
		return fmt.Errorf("query is not allowed")
	}
	if u.Fragment != "" {
		return fmt.Errorf("fragment is not allowed")
	}
	return nil
}
