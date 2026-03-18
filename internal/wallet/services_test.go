package wallet

import (
	"context"
	"os"
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	sdkchainhash "github.com/bsv-blockchain/go-sdk/chainhash"
)

func tmpServices(t *testing.T) *AnvilServices {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-wallet-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-wallet-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, err := spv.NewProofStore(pdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })

	return NewAnvilServices(hs, ps, nil)
}

func TestServicesCurrentHeight(t *testing.T) {
	svc := tmpServices(t)
	h, err := svc.CurrentHeight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h != 0 {
		t.Fatalf("expected height 0, got %d", h)
	}
}

func TestServicesIsValidRootForHeight(t *testing.T) {
	svc := tmpServices(t)
	root, _ := sdkchainhash.NewHashFromHex("0000000000000000000000000000000000000000000000000000000000000000")
	valid, err := svc.IsValidRootForHeight(context.Background(), root, 999)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected invalid for missing height")
	}
}

func TestServicesChainHeaderByHeight(t *testing.T) {
	svc := tmpServices(t)
	hdr, err := svc.ChainHeaderByHeight(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Hash == "" {
		t.Fatal("expected non-empty hash for genesis")
	}
	if hdr.Height != 0 {
		t.Fatalf("expected height 0, got %d", hdr.Height)
	}
}

func TestServicesFindChainTipHeader(t *testing.T) {
	svc := tmpServices(t)
	hdr, err := svc.FindChainTipHeader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Height != 0 {
		t.Fatalf("expected tip height 0, got %d", hdr.Height)
	}
}

func TestServicesNLockTimeIsFinal(t *testing.T) {
	svc := tmpServices(t)
	final, err := svc.NLockTimeIsFinal(context.Background(), uint32(0))
	if err != nil {
		t.Fatal(err)
	}
	if !final {
		t.Fatal("expected final")
	}
}

func TestServicesGetStatusForTxIDs(t *testing.T) {
	svc := tmpServices(t)
	result, err := svc.GetStatusForTxIDs(context.Background(), []string{"abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	if result.Results[0].Status != "unknown" {
		t.Fatalf("expected unknown, got %s", result.Results[0].Status)
	}
}

func TestServicesRawTxNotFound(t *testing.T) {
	svc := tmpServices(t)
	result, err := svc.RawTx(context.Background(), "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if result.RawTx != nil {
		t.Fatal("expected nil raw tx for missing txid")
	}
}
