package overlay

import (
	"encoding/hex"
	"log/slog"
	"os"
	"testing"

	"github.com/BSVanon/Anvil/pkg/brc"
	"github.com/GorillaPool/go-junglebus/models"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestJungleBusOnTransaction builds a real tx containing a SHIP token,
// serializes it, and feeds it through the JungleBus handler to verify
// the full canonical discovery path: raw tx -> parse outputs -> decode
// BRC-48 push-drop -> validate SHIP -> add to directory.
func TestJungleBusOnTransaction(t *testing.T) {
	dir := tmpDirectory(t)
	disc := NewDiscoverer(dir, slog.Default())

	key, _ := ec.PrivateKeyFromWif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S")

	// Build a SHIP token script
	shipScript, _, err := brc.BuildSHIPScript(key, "jb-peer.example.com:8333", "forge:mainnet")
	if err != nil {
		t.Fatal(err)
	}

	// Build a transaction containing the SHIP token as an output
	tx := transaction.NewTransaction()
	tx.Version = 1
	lockingScript := script.NewFromBytes(shipScript)
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1,
		LockingScript: lockingScript,
	})

	rawTx := tx.Bytes()
	txid := tx.TxID().String()

	// Create a JungleBus subscriber with our discoverer
	sub := &JungleBusSubscriber{
		discoverer: disc,
		logger:     slog.Default(),
	}

	// Feed the transaction through the handler
	sub.onTransaction(&models.TransactionResponse{
		Id:          txid,
		BlockHeight: 900000,
		Transaction: rawTx,
	})

	// The SHIP token should now be in the directory
	peers, err := dir.LookupSHIPByTopic("forge:mainnet")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer from JungleBus discovery, got %d", len(peers))
	}
	if peers[0].Domain != "jb-peer.example.com:8333" {
		t.Fatalf("expected domain jb-peer.example.com:8333, got %s", peers[0].Domain)
	}
	if peers[0].TxID != txid {
		t.Fatalf("expected txid %s, got %s", txid, peers[0].TxID)
	}

	t.Logf("JungleBus discovery success: txid=%s domain=%s", txid, peers[0].Domain)
}

func TestJungleBusIgnoresNonTokenOutputs(t *testing.T) {
	dir := tmpDirectory(t)
	disc := NewDiscoverer(dir, slog.Default())

	// Build a plain P2PKH transaction (no BRC-48 tokens)
	tx := transaction.NewTransaction()
	tx.Version = 1
	p2pkh, _ := script.NewFromHex("76a9140000000000000000000000000000000000000000ac")
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: p2pkh,
	})

	sub := &JungleBusSubscriber{
		discoverer: disc,
		logger:     slog.Default(),
	}

	sub.onTransaction(&models.TransactionResponse{
		Transaction: tx.Bytes(),
	})

	// Nothing should be in the directory
	if dir.CountSHIP() != 0 {
		t.Fatal("expected 0 SHIP entries for non-token tx")
	}
}

func TestJungleBusHandlesEmptyTx(t *testing.T) {
	dir := tmpDirectory(t)
	disc := NewDiscoverer(dir, slog.Default())

	sub := &JungleBusSubscriber{
		discoverer: disc,
		logger:     slog.Default(),
	}

	// Should not panic
	sub.onTransaction(&models.TransactionResponse{
		Transaction: nil,
	})
	sub.onTransaction(&models.TransactionResponse{
		Transaction: []byte{},
	})
}

// Suppress unused imports
var _ = hex.EncodeToString
var _ = os.TempDir
