package overlay

import (
	"encoding/json"
	"fmt"
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

// PeerEntry is a discovered SHIP peer for a topic.
type PeerEntry struct {
	IdentityPub  string    `json:"identity_pub"`            // compressed pubkey hex
	Domain       string    `json:"domain"`                  // e.g. "relay.example.com:8333"
	NodeName     string    `json:"node_name,omitempty"`      // human-readable name from config
	Topic        string    `json:"topic"`                   // e.g. "anvil:mainnet"
	TxID         string    `json:"txid"`                    // on-chain tx containing the SHIP token
	OutputIndex  int       `json:"output_index"`
	DiscoveredAt time.Time `json:"discovered_at"`
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
	db *leveldb.DB
	mu sync.RWMutex
}

// NewDirectory opens or creates an overlay directory.
func NewDirectory(path string) (*Directory, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open overlay directory: %w", err)
	}
	return &Directory{db: db}, nil
}

// Close closes the underlying LevelDB.
func (d *Directory) Close() error {
	return d.db.Close()
}

// AddSHIPPeer stores a SHIP peer entry, validated against its BRC-42 derivation.
func (d *Directory) AddSHIPPeer(entry *PeerEntry, script []byte) error {
	// Validate the SHIP token script against BRC-42 derivation
	_, err := brc.ValidateSHIPToken(script)
	if err != nil {
		return fmt.Errorf("invalid SHIP token: %w", err)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	key := shipKey(entry.Topic, entry.IdentityPub)
	d.mu.Lock()
	defer d.mu.Unlock()
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
func (d *Directory) ForEachSHIP(fn func(identity, domain, nodeName, topic string) bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	iter := d.db.NewIterator(util.BytesPrefix(prefixSHIP), nil)
	defer iter.Release()
	for iter.Next() {
		var entry PeerEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			continue
		}
		if !fn(entry.IdentityPub, entry.Domain, entry.NodeName, entry.Topic) {
			break
		}
	}
}

// AddSHIPPeerFromGossip stores a SHIP peer received from a trusted mesh peer.
// Skips SHIP script validation since the peer has already been authenticated.
// Satisfies gossip.OverlayDirectory interface.
func (d *Directory) AddSHIPPeerFromGossip(identity, domain, nodeName, topic string) error {
	entry := &PeerEntry{
		IdentityPub:  identity,
		Domain:       domain,
		NodeName:     nodeName,
		Topic:        topic,
		TxID:         "gossip",
		DiscoveredAt: time.Now(),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	key := shipKey(topic, identity)
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.db.Put(key, data, nil)
}

func shipKey(topic, identityPub string) []byte {
	prefix := identityPub
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	return append(append([]byte{}, prefixSHIP...), []byte(topic+":"+prefix)...)
}

func slapKey(domain, identityPub string) []byte {
	prefix := identityPub
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	return append(append([]byte{}, prefixSLAP...), []byte(domain+":"+prefix)...)
}
