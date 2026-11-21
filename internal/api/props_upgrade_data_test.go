package api

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/spv"
	p2pchainhash "github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

func TestVersion340StoresReopenWithoutDataLoss(t *testing.T) {
	root := t.TempDir()

	headerPath := filepath.Join(root, "headers")
	headerStore, err := headers.NewTestStore(headerPath)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := headerStore.HashAtHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	merkle, err := p2pchainhash.NewHashFromStr("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	header := wire.NewBlockHeader(1, genesis, merkle, 0x1d00ffff, 12345)
	header.Timestamp = time.Unix(1231006506, 0)
	if err := headerStore.AddHeaders(1, []*wire.BlockHeader{header}); err != nil {
		t.Fatal(err)
	}
	wantHeader, err := headerStore.HeaderAtHeight(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := headerStore.Close(); err != nil {
		t.Fatal(err)
	}
	headerStore, err = headers.NewStore(headerPath)
	if err != nil {
		t.Fatal(err)
	}
	gotHeader, err := headerStore.HeaderAtHeight(1)
	if err != nil || headerStore.Tip() != 1 || !bytes.Equal(gotHeader, wantHeader) {
		t.Fatalf("reopened headers: tip=%d bytes_equal=%v err=%v", headerStore.Tip(), bytes.Equal(gotHeader, wantHeader), err)
	}
	if err := headerStore.Close(); err != nil {
		t.Fatal(err)
	}

	proofPath := filepath.Join(root, "proofs")
	proofStore, err := spv.NewProofStore(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	wallet := ordtracktest.NewWallet(t)
	tx := wallet.Fund(ordtracktest.Out{Sats: 1000})
	beef, err := tx.AtomicBEEF(true)
	if err != nil {
		t.Fatal(err)
	}
	txid, err := proofStore.StoreBEEF(beef)
	if err != nil {
		t.Fatal(err)
	}
	if err := proofStore.Close(); err != nil {
		t.Fatal(err)
	}
	proofStore, err = spv.NewProofStore(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	gotBEEF, err := proofStore.GetBEEF(txid)
	if err != nil || !bytes.Equal(gotBEEF, beef) {
		t.Fatalf("reopened proof bytes_equal=%v err=%v", bytes.Equal(gotBEEF, beef), err)
	}
	if err := proofStore.Close(); err != nil {
		t.Fatal(err)
	}

	overlayPath := filepath.Join(root, "overlay")
	directory, err := overlay.NewDirectory(overlayPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := directory.AddSHIPPeerFromGossip(identity, "peer.example", "peer", "3.4.0", "anvil:mainnet"); err != nil {
		t.Fatal(err)
	}
	wantPeers, err := directory.LookupSHIPByTopic("anvil:mainnet")
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	directory, err = overlay.NewDirectory(overlayPath)
	if err != nil {
		t.Fatal(err)
	}
	gotPeers, err := directory.LookupSHIPByTopic("anvil:mainnet")
	if err != nil || !reflect.DeepEqual(gotPeers, wantPeers) {
		t.Fatalf("reopened overlay peers = %+v, want %+v, err=%v", gotPeers, wantPeers, err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBRC121JournalExistsOnlyWhenPaymentFeatureStarts(t *testing.T) {
	root := t.TempDir()
	NewServer(ServerConfig{DataDir: root})
	if _, err := os.Stat(filepath.Join(root, "brc121-journal")); !os.IsNotExist(err) {
		t.Fatalf("payment-off server created BRC-121 journal: %v", err)
	}
	fixture := newBRC121Fix(t, 1)
	if _, err := os.Stat(filepath.Join(fixture.dir, "brc121-journal")); err != nil {
		t.Fatalf("payment-on server did not create BRC-121 journal: %v", err)
	}
}
