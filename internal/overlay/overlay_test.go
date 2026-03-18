package overlay

import (
	"encoding/hex"
	"log/slog"
	"os"
	"testing"

	"github.com/BSVanon/Anvil/pkg/brc"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func testKey() *ec.PrivateKey {
	key, _ := ec.PrivateKeyFromWif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S")
	return key
}

func tmpDirectory(t *testing.T) *Directory {
	t.Helper()
	dir, _ := os.MkdirTemp("", "anvil-overlay-test-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	d, err := NewDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// --- SHIP ---

func TestAddAndLookupSHIPPeer(t *testing.T) {
	d := tmpDirectory(t)
	key := testKey()

	script, _, err := brc.BuildSHIPScript(key, "relay.example.com:8333", "forge:mainnet")
	if err != nil {
		t.Fatal(err)
	}

	entry := &PeerEntry{
		IdentityPub: hex.EncodeToString(key.PubKey().Compressed()),
		Domain:      "relay.example.com:8333",
		Topic:       "forge:mainnet",
		TxID:        "abc123",
		OutputIndex: 0,
	}

	if err := d.AddSHIPPeer(entry, script); err != nil {
		t.Fatal(err)
	}

	peers, err := d.LookupSHIPByTopic("forge:mainnet")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Domain != "relay.example.com:8333" {
		t.Fatalf("expected domain relay.example.com:8333, got %s", peers[0].Domain)
	}
}

func TestSHIPRejectsInvalidScript(t *testing.T) {
	d := tmpDirectory(t)
	entry := &PeerEntry{
		IdentityPub: "deadbeef",
		Domain:      "bad.com",
		Topic:       "forge:mainnet",
	}
	err := d.AddSHIPPeer(entry, []byte("not a valid script"))
	if err == nil {
		t.Fatal("expected error for invalid SHIP script")
	}
}

func TestLookupSHIPByTopicEmpty(t *testing.T) {
	d := tmpDirectory(t)
	peers, err := d.LookupSHIPByTopic("nonexistent:topic")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers, got %d", len(peers))
	}
}

func TestCountSHIP(t *testing.T) {
	d := tmpDirectory(t)
	if d.CountSHIP() != 0 {
		t.Fatal("expected 0")
	}

	key := testKey()
	script, _, _ := brc.BuildSHIPScript(key, "a.com", "forge:mainnet")
	d.AddSHIPPeer(&PeerEntry{
		IdentityPub: hex.EncodeToString(key.PubKey().Compressed()),
		Domain:      "a.com",
		Topic:       "forge:mainnet",
	}, script)

	if d.CountSHIP() != 1 {
		t.Fatalf("expected 1, got %d", d.CountSHIP())
	}
}

// --- SLAP ---

func TestAddAndLookupSLAPProvider(t *testing.T) {
	d := tmpDirectory(t)
	key := testKey()

	script, _, err := brc.BuildSLAPScript(key, "overlay.example.com", "SHIP")
	if err != nil {
		t.Fatal(err)
	}

	entry := &ProviderEntry{
		IdentityPub: hex.EncodeToString(key.PubKey().Compressed()),
		Domain:      "overlay.example.com",
		Provider:    "SHIP",
		TxID:        "def456",
		OutputIndex: 0,
	}

	if err := d.AddSLAPProvider(entry, script); err != nil {
		t.Fatal(err)
	}

	providers, err := d.LookupSLAPByDomain("overlay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}
	if providers[0].Provider != "SHIP" {
		t.Fatalf("expected provider SHIP, got %s", providers[0].Provider)
	}
}

// --- Discoverer ---

func TestDiscovererProcessSHIPScript(t *testing.T) {
	d := tmpDirectory(t)
	disc := NewDiscoverer(d, slog.Default())
	key := testKey()

	script, _, _ := brc.BuildSHIPScript(key, "peer.example.com:8333", "forge:mainnet")

	if err := disc.ProcessSHIPScript(script, "tx123", 0); err != nil {
		t.Fatal(err)
	}

	peers, _ := disc.DiscoverPeersForTopic("forge:mainnet")
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].TxID != "tx123" {
		t.Fatalf("expected txid tx123, got %s", peers[0].TxID)
	}
}

func TestDiscovererProcessSLAPScript(t *testing.T) {
	d := tmpDirectory(t)
	disc := NewDiscoverer(d, slog.Default())
	key := testKey()

	script, _, _ := brc.BuildSLAPScript(key, "provider.example.com", "SHIP")

	if err := disc.ProcessSLAPScript(script, "tx456", 1); err != nil {
		t.Fatal(err)
	}

	providers, _ := d.LookupSLAPByDomain("provider.example.com")
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}
}

func TestDiscovererRejectsInvalidScript(t *testing.T) {
	d := tmpDirectory(t)
	disc := NewDiscoverer(d, slog.Default())

	if err := disc.ProcessSHIPScript([]byte("garbage"), "tx", 0); err == nil {
		t.Fatal("expected error for invalid script")
	}
}
