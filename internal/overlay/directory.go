package overlay

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/pkg/brc"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var (
	prefixSHIP = []byte("ship:") // ship:<topic>:<identity_prefix> → PeerEntry JSON
	prefixSLAP = []byte("slap:") // slap:<domain>:<identity_prefix> → ProviderEntry JSON
)

// DefaultSHIPTTL is the maximum age for SHIP entries before they're pruned.
// Entries refreshed by gossip or Bootstrap within this window survive.
const DefaultSHIPTTL = 6 * time.Hour

// PeerEntry is a discovered SHIP peer for a topic.
type PeerEntry struct {
	IdentityPub  string    `json:"identity_pub"`            // compressed pubkey hex
	Domain       string    `json:"domain"`                  // e.g. "relay.example.com:8333"
	NodeName     string    `json:"node_name,omitempty"`      // human-readable name from config
	Version      string    `json:"version,omitempty"`        // node software version (e.g. "0.5.1")
	Topic        string    `json:"topic"`                   // e.g. "anvil:mainnet"
	TxID         string    `json:"txid"`                    // on-chain tx or "self-registered" or "gossip"
	OutputIndex  int       `json:"output_index"`
	DiscoveredAt time.Time `json:"discovered_at"`
	LastSeen     time.Time `json:"last_seen"`               // refreshed on every write (gossip, bootstrap)
}

// ProviderEntry is a discovered SLAP service provider.
type ProviderEntry struct {
	IdentityPub  string    `json:"identity_pub"`
	Domain       string    `json:"domain"`
	Provider     string    `json:"provider"` // e.g. "SHIP"
	TxID         string    `json:"txid"`
	OutputIndex  int       `json:"output_index"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Directory stores and queries SHIP/SLAP token registrations discovered
// from the overlay network. Backed by LevelDB for persistence.
type Directory struct {
	db  *leveldb.DB
	mu  sync.RWMutex
	ttl time.Duration
}

// NewDirectory opens or creates an overlay directory.
func NewDirectory(path string) (*Directory, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open overlay directory: %w", err)
	}
	return &Directory{db: db, ttl: DefaultSHIPTTL}, nil
}

// Close closes the underlying LevelDB.
func (d *Directory) Close() error {
	return d.db.Close()
}

// DB returns the underlying LevelDB for shared use by the overlay engine.
func (d *Directory) DB() *leveldb.DB {
	return d.db
}

// AddSHIPPeer stores a SHIP peer entry, validated against its BRC-42 derivation.
// Deduplicates by domain+topic to handle node re-keying.
func (d *Directory) AddSHIPPeer(entry *PeerEntry, script []byte) error {
	_, err := brc.ValidateSHIPToken(script)
	if err != nil {
		return fmt.Errorf("invalid SHIP token: %w", err)
	}

	entry.LastSeen = time.Now()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	key := shipKey(entry.Topic, entry.IdentityPub)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.removeStaleDomainLocked(entry.Topic, entry.Domain, entry.IdentityPub)
	return d.db.Put(key, data, nil)
}

// AddSLAPProvider stores a SLAP provider entry, validated against BRC-42.
func (d *Directory) AddSLAPProvider(entry *ProviderEntry, script []byte) error {
	_, err := brc.ValidateSLAPToken(script)
	if err != nil {
		return fmt.Errorf("invalid SLAP token: %w", err)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	key := slapKey(entry.Domain, entry.IdentityPub)
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.db.Put(key, data, nil)
}

// LookupSHIPByTopic returns all SHIP peers registered for the given topic.
func (d *Directory) LookupSHIPByTopic(topic string) ([]*PeerEntry, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	prefix := append(append([]byte{}, prefixSHIP...), []byte(topic+":")...)
	iter := d.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	var results []*PeerEntry
	for iter.Next() {
		var entry PeerEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			continue
		}
		results = append(results, &entry)
	}
	return results, iter.Error()
}

// LookupSLAPByDomain returns all SLAP providers for a domain.
func (d *Directory) LookupSLAPByDomain(domain string) ([]*ProviderEntry, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	prefix := append(append([]byte{}, prefixSLAP...), []byte(domain+":")...)
	iter := d.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	var results []*ProviderEntry
	for iter.Next() {
		var entry ProviderEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			continue
		}
		results = append(results, &entry)
	}
	return results, iter.Error()
}

// RemoveSHIPPeer removes a SHIP peer entry from the directory.
func (d *Directory) RemoveSHIPPeer(topic, identityPub string) error {
	key := shipKey(topic, identityPub)
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.db.Delete(key, nil)
}

// CountSHIP returns the total number of SHIP entries.
func (d *Directory) CountSHIP() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	count := 0
	iter := d.db.NewIterator(util.BytesPrefix(prefixSHIP), nil)
	defer iter.Release()
	for iter.Next() {
		count++
	}
	return count
}

// ForEachSHIP iterates all SHIP registrations, calling fn for each.
// Satisfies gossip.OverlayDirectory interface.
func (d *Directory) ForEachSHIP(fn func(identity, domain, nodeName, version, topic string) bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	iter := d.db.NewIterator(util.BytesPrefix(prefixSHIP), nil)
	defer iter.Release()
	for iter.Next() {
		var entry PeerEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			continue
		}
		if !fn(entry.IdentityPub, entry.Domain, entry.NodeName, entry.Version, entry.Topic) {
			break
		}
	}
}

// AddSHIPPeerFromGossip stores a SHIP peer received from a trusted mesh peer.
// Deduplicates by domain+topic: if a different identity registers the same
// domain+topic, the old entry is removed (handles node re-keying).
// Satisfies gossip.OverlayDirectory interface.
func (d *Directory) AddSHIPPeerFromGossip(identity, domain, nodeName, version, topic string) error {
	now := time.Now()
	entry := &PeerEntry{
		IdentityPub:  identity,
		Domain:       domain,
		NodeName:     nodeName,
		Version:      version,
		Topic:        topic,
		TxID:         "gossip",
		DiscoveredAt: now,
		LastSeen:     now,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	key := shipKey(topic, identity)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.removeStaleDomainLocked(topic, domain, identity)
	return d.db.Put(key, data, nil)
}

// SweepExpired removes SHIP entries whose LastSeen is older than the TTL.
// Returns the number of entries removed. Call periodically (e.g. every 5 min).
func (d *Directory) SweepExpired() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-d.ttl)
	var toDelete [][]byte

	iter := d.db.NewIterator(util.BytesPrefix(prefixSHIP), nil)
	defer iter.Release()
	for iter.Next() {
		var entry PeerEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			continue
		}
		seen := entry.LastSeen
		if seen.IsZero() {
			seen = entry.DiscoveredAt
		}
		if seen.Before(cutoff) {
			key := make([]byte, len(iter.Key()))
			copy(key, iter.Key())
			toDelete = append(toDelete, key)
		}
	}
	for _, key := range toDelete {
		_ = d.db.Delete(key, nil) // best-effort cleanup
	}
	return len(toDelete)
}

// CleanupOnBoot removes SHIP entries that are stale on startup:
// - Entries older than TTL
// - Entries for local domains with a different identity (re-key)
// Call once at startup before Bootstrap self-registers.
func (d *Directory) CleanupOnBoot(localDomains map[string]string, logger *slog.Logger) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-d.ttl)
	var toDelete [][]byte

	iter := d.db.NewIterator(util.BytesPrefix(prefixSHIP), nil)
	defer iter.Release()
	for iter.Next() {
		var entry PeerEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			continue
		}

		shouldDelete := false

		// Check TTL
		seen := entry.LastSeen
		if seen.IsZero() {
			seen = entry.DiscoveredAt
		}
		if seen.Before(cutoff) {
			shouldDelete = true
			if logger != nil {
				logger.Info("overlay cleanup: expired entry",
					"domain", entry.Domain,
					"identity", truncID(entry.IdentityPub),
					"last_seen", seen.Format(time.RFC3339))
			}
		}

		// Check re-key: local domain with different identity
		if currentID, ok := localDomains[entry.Domain]; ok && entry.IdentityPub != currentID {
			shouldDelete = true
			if logger != nil {
				logger.Info("overlay cleanup: stale re-key entry",
					"domain", entry.Domain,
					"old_identity", truncID(entry.IdentityPub),
					"current_identity", truncID(currentID))
			}
		}

		if shouldDelete {
			key := make([]byte, len(iter.Key()))
			copy(key, iter.Key())
			toDelete = append(toDelete, key)
		}
	}
	for _, key := range toDelete {
		_ = d.db.Delete(key, nil) // best-effort cleanup
	}
	return len(toDelete)
}

// removeStaleDomainLocked removes SHIP entries for a domain+topic that belong
// to a different identity than the one being registered. Must be called with d.mu held.
func (d *Directory) removeStaleDomainLocked(topic, domain, currentIdentity string) {
	prefix := append(append([]byte{}, prefixSHIP...), []byte(topic+":")...)
	iter := d.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	var toDelete [][]byte
	for iter.Next() {
		var entry PeerEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			continue
		}
		if entry.Domain == domain && entry.IdentityPub != currentIdentity {
			key := make([]byte, len(iter.Key()))
			copy(key, iter.Key())
			toDelete = append(toDelete, key)
		}
	}
	for _, key := range toDelete {
		_ = d.db.Delete(key, nil) // best-effort cleanup
	}
}

// RemoveSHIPPeerByIdentity removes all SHIP registrations for a given identity.
// Used by slash enforcement to deregister misbehaving peers.
func (d *Directory) RemoveSHIPPeerByIdentity(identity string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var toDelete [][]byte
	iter := d.db.NewIterator(util.BytesPrefix(prefixSHIP), nil)
	defer iter.Release()
	for iter.Next() {
		var entry PeerEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			continue
		}
		if entry.IdentityPub == identity {
			key := make([]byte, len(iter.Key()))
			copy(key, iter.Key())
			toDelete = append(toDelete, key)
		}
	}
	for _, key := range toDelete {
		_ = d.db.Delete(key, nil) // best-effort cleanup
	}
}

func shipKey(topic, identityPub string) []byte {
	prefix := identityPub
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	return append(append([]byte{}, prefixSHIP...), []byte(topic+":"+prefix)...)
}

func truncID(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func slapKey(domain, identityPub string) []byte {
	prefix := identityPub
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	return append(append([]byte{}, prefixSLAP...), []byte(domain+":"+prefix)...)
}
