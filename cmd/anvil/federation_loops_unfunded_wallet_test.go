package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/overlay/federation"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/BSVanon/Anvil/internal/overlay/v3engine"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	anvilwallet "github.com/BSVanon/Anvil/internal/wallet"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestRunSyncAdvertisements_UnfundedWalletLogsClearlyAndKeepsRunning is
// item 9 (K3/F5): what happens when the node wallet cannot afford the
// SHIP/SLAP adverts for tm_messagebox/ls_messagebox (or any other
// topic). A real, freshly-created NodeWallet (a fresh WIF, never funded
// by any deposit or internalized transaction -- zero balance by
// construction, exactly the "a few sats" live-node case item 9 asks
// about) is wired as a real federation.Advertiser against a real
// v3engine.New instance, then SyncAdvertisements is called directly,
// with slog's process-wide default temporarily redirected to a buffer:
// go-overlay-services' own SyncAdvertisements logs a failure via the
// bare package-level slog.Error, i.e. slog.Default() -- the same logger
// cmd/anvil's own main.go uses (`logger := slog.Default()`, main.go:105;
// no slog.SetDefault call anywhere in cmd/anvil), so this redirect
// observes exactly what a real node's own log stream would show.
//
// Found: SyncAdvertisements (go-overlay-services engine.go:888-953)
// never returns the CreateAdvertisements error to its caller -- it logs
// and swallows it, returning nil. The underlying failure is
// go-wallet-toolbox's own insufficient-funds error
// (pkg/storage/internal/actions/create.go:268, wrapping
// pkg/internal/storage/funder/errfunder.ErrNotEnoughFunds, "not enough
// funds"), wrapped once more by
// internal/overlay/federation/advertiser.go's CreateAdvertisements
// (":161", "federation: advertiser: create action: %w"). So: no crash
// (SyncAdvertisements returns nil; runSyncAdvertisements's own retry
// cadence is cfg.Overlay.AdvertiseIntervalSecs, default 1800s -- never a
// 1-second storm, confirmed separately by this file's sibling
// TestRunSyncAdvertisements_SurvivesAPanickingRun for that loop's panic
// recovery), the node keeps serving (the engine is still fully usable
// afterward), and the log line that does fire names the real cause
// clearly enough for an operator to act on. No cmd/anvil fix was needed
// -- this test exists to prove, not assume, that finding, and to catch
// a regression in either the swallow-and-log behaviour or the error's
// clarity.
func TestRunSyncAdvertisements_UnfundedWalletLogsClearlyAndKeepsRunning(t *testing.T) {
	root := t.TempDir()

	hs, err := headers.NewTestStore(filepath.Join(root, "h"))
	if err != nil {
		t.Fatalf("headers.NewTestStore: %v", err)
	}
	t.Cleanup(func() { _ = hs.Close() })
	ps, err := spv.NewProofStore(filepath.Join(root, "proofs"))
	if err != nil {
		t.Fatalf("spv.NewProofStore: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	mempool := txrelay.NewMempool()
	broadcaster := txrelay.NewBroadcaster(mempool, nil, slog.Default())

	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	walletDir := filepath.Join(root, "wallet")
	if err := os.MkdirAll(walletDir, 0o755); err != nil {
		t.Fatalf("mkdir wallet dir: %v", err)
	}
	nw, err := anvilwallet.New(priv.Wif(), walletDir, hs, ps, broadcaster, nil, slog.Default())
	if err != nil {
		t.Fatalf("anvilwallet.New: %v", err)
	}
	t.Cleanup(nw.Close)

	dir, err := anviloverlay.NewDirectory(filepath.Join(root, "overlay"))
	if err != nil {
		t.Fatalf("open overlay directory: %v", err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	overlaytest.SeedFundingBlock(t, hs)
	eng, err := v3engine.New(&v3engine.Config{
		Storage:      anvilstorage.New(dir.DB()),
		HeadersStore: hs,
		LookupDB:     dir.DB(),
		HostingURL:   "https://my-anvil.example.org",
	})
	if err != nil {
		t.Fatalf("v3engine.New: %v", err)
	}
	eng.Advertiser = federation.NewAdvertiser(nw.Wallet(), "https://my-anvil.example.org",
		federation.NewSHIPStorage(dir.DB()), federation.NewSLAPStorage(dir.DB()), anvilstorage.New(dir.DB()))

	var logged syncBuffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	if err := eng.SyncAdvertisements(context.Background()); err != nil {
		t.Fatalf("SyncAdvertisements returned an error instead of swallowing it: %v", err)
	}

	// The node must still serve: a basic, already-exercised-elsewhere
	// engine call must still work afterward -- a crash or corrupted
	// engine state would show up here.
	if _, ok := eng.GetLookupService(topics.MessageBoxLookupServiceName); !ok {
		t.Fatal("engine lost its registered ls_messagebox lookup service after SyncAdvertisements -- it should still be serving")
	}

	out := logged.String()
	if !strings.Contains(out, "failed to create SHIP/SLAP advertisements") {
		t.Fatalf("expected a clear warning naming SHIP/SLAP advertisement creation; got:\n%s", out)
	}
	if !strings.Contains(out, "not enough funds") {
		t.Fatalf("expected the warning to name the real cause (not enough funds); got:\n%s", out)
	}
}
