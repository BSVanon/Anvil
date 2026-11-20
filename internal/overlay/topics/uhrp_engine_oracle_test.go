package topics_test

// This file holds the TS-oracle cross-check for {uhrpUrl} answers: it
// feeds real @bsv/sdk's PushDrop decode loop (mirroring
// StorageDownloader.ts's resolve()) both a canonical BRC-26 answer (must
// decode cleanly) and a LEGACY-format advert (must throw). Split out of
// uhrp_engine_test.go, which was growing past this package's established
// per-file size norm once the fix pass's negative-case addition
// (re-review RISKS item 4) landed here; this file and uhrp_engine_test.go
// together replace what was one file, with no behaviour change to the
// moved code (only the extracted exec.Command/CombinedOutput plumbing was
// factored into runUHRPOracle so the new negative case doesn't duplicate
// it).

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	sdkstorage "github.com/bsv-blockchain/go-sdk/storage"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// uhrpStorageDownloaderOracleJS mirrors ts-sdk's StorageDownloader.ts
// resolve() decode loop exactly (reviewer scratch ts/sd.mjs, reused not
// re-derived): PushDrop-decode, then read the expiry varint and URL
// field the same way resolve() does. A throw means a real client would
// drop the output — must never happen for a {uhrpUrl} answer, since
// those are BRC-26-only (spec item 1 / B1).
const uhrpStorageDownloaderOracleJS = `
const sdk = await import(process.env.SDK)
const { PushDrop, Utils, LockingScript } = sdk
const items = process.argv.slice(2)
for (const hex of items) {
  try {
    const { fields } = PushDrop.decode(LockingScript.fromHex(hex))
    const expiryTime = new Utils.Reader(fields[3]).readVarIntNum()
    const url = Utils.toUTF8(fields[2])
    console.log('OK expiry=' + expiryTime + ' url=' + url)
  } catch (e) {
    console.log('THROWS (resolve() rejects): ' + (e && e.message || e))
  }
}
`

// findLocalBSVSDK locates a local @bsv/sdk ESM build to run the oracle
// against, preferring the same SDK version/path set the cold review's
// own TS vectors were generated from. Returns "" if none is found.
func findLocalBSVSDK() string {
	for _, p := range []string{
		"/home/robert/Documents/SendBSV-Foundry/node_modules/@bsv/sdk/dist/esm/mod.js",
		"/home/robert/Documents/Anvil-Swap/node_modules/@bsv/sdk/dist/esm/mod.js",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// runUHRPOracle runs uhrpStorageDownloaderOracleJS against one or more
// locking-script hexes and returns its combined stdout. Shared by the
// positive (BRC-26, must decode) and negative (LEGACY, must throw) cases
// below so both drive the exact same oracle script.
func runUHRPOracle(t *testing.T, oraclePath, nodePath, sdkPath string, scriptHexes []string) string {
	t.Helper()
	cmd := exec.Command(nodePath, append([]string{oraclePath}, scriptHexes...)...) // #nosec G204 -- nodePath from exec.LookPath, args are hex we just encoded
	cmd.Env = append(os.Environ(), "SDK="+sdkPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node oracle: %v\n%s", err, out)
	}
	return string(out)
}

// TestUHRPEngine_UhrpUrlAnswersDecodeInCanonicalStorageDownloader is the
// spec item 6 oracle requirement: admit two fresh BRC-26 adverts through
// the real engine, resolve each by its canonical uhrp:// URL (hydrating
// genuine BEEF via Storage, not test-built bytes), and feed every
// resulting locking script to a Node process running the real @bsv/sdk.
// Skips, never fails, when node or a local @bsv/sdk build isn't available.
//
// Re-review RISKS item 4 extends this with the negative case: a
// LEGACY-format advert script (topics.BuildUHRPScript — OP_RETURN-shaped,
// never PushDrop-shaped) fed to the identical oracle must THROW, proving
// the oracle would actually catch it if canonicalOnly ever let one leak
// into a {uhrpUrl} answer — not just that the oracle accepts what it's
// supposed to.
func TestUHRPEngine_UhrpUrlAnswersDecodeInCanonicalStorageDownloader(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH — skipping canonical TS oracle cross-check")
	}
	sdkPath := findLocalBSVSDK()
	if sdkPath == "" {
		t.Skip("no local @bsv/sdk ESM build found — skipping canonical TS oracle cross-check")
	}

	ctx := context.Background()
	eng := newFixPassTestEngine(t)

	fixtures := []struct {
		hash []byte
		url  string
	}{
		{freshHash32(0x81), "https://oracle1.example.test/a"},
		{freshHash32(0x82), "https://oracle2.example.test/b"},
	}
	var uhrpURLs []string
	for _, fx := range fixtures {
		advert := buildFreshBRC26Advert(t, fx.hash, fx.url)
		tx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: advert.script, Satoshis: 1000})
		steak := submitUHRPTx(t, eng, tx)
		if inst, ok := steak[topics.UHRPTopicName]; !ok || inst == nil || len(inst.OutputsToAdmit) != 1 {
			t.Fatalf("expected fixture advert admitted, got %+v", inst)
		}
		b58, err := sdkstorage.GetURLForHash(fx.hash)
		if err != nil {
			t.Fatalf("GetURLForHash: %v", err)
		}
		uhrpURLs = append(uhrpURLs, "uhrp://"+b58)
	}

	var scriptHexes []string
	for _, u := range uhrpURLs {
		q, err := json.Marshal(topics.UHRPLookupQuery{UhrpUrl: u})
		if err != nil {
			t.Fatalf("marshal query: %v", err)
		}
		answer, err := eng.Lookup(ctx, &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
		if err != nil {
			t.Fatalf("lookup %q: %v", u, err)
		}
		if len(answer.Outputs) == 0 {
			t.Fatalf("lookup %q: expected at least one hydrated output, got none", u)
		}
		for _, o := range answer.Outputs {
			_, tx, _, err := transaction.ParseBeef(o.Beef)
			if err != nil {
				t.Fatalf("parse hydrated beef for %q: %v", u, err)
			}
			if tx == nil || int(o.OutputIndex) >= len(tx.Outputs) {
				t.Fatalf("hydrated beef for %q: no output at index %d", u, o.OutputIndex)
			}
			ls := tx.Outputs[o.OutputIndex].LockingScript
			if ls == nil {
				t.Fatalf("hydrated beef for %q: output %d has no locking script", u, o.OutputIndex)
			}
			scriptHexes = append(scriptHexes, hex.EncodeToString(ls.Bytes()))
		}
	}

	oraclePath := filepath.Join(t.TempDir(), "uhrp_storage_downloader_oracle.mjs")
	if err := os.WriteFile(oraclePath, []byte(uhrpStorageDownloaderOracleJS), 0o600); err != nil {
		t.Fatalf("write oracle script: %v", err)
	}
	out := runUHRPOracle(t, oraclePath, nodePath, sdkPath, scriptHexes)
	if strings.Contains(out, "THROWS") {
		t.Fatalf("canonical StorageDownloader.resolve logic rejected a {uhrpUrl} answer:\n%s", out)
	}
	if got := strings.Count(out, "OK expiry="); got != len(scriptHexes) {
		t.Fatalf("expected %d canonical-decodes, got %d:\n%s", len(scriptHexes), got, out)
	}

	// Negative case (re-review RISKS item 4): a LEGACY-format advert is
	// never PushDrop-shaped (uhrp_legacy.go: OP_FALSE OP_RETURN "UHRP"
	// <hash>...), so the identical oracle must THROW on it — proof that
	// canonicalOnly's uhrpUrl-is-BRC26-only rule (filterUHRPRecords rule 3,
	// uhrp_filter.go) is actually load-bearing, not just untested-but-
	// assumed.
	legacyHash := topics.HashContent([]byte("uhrp engine oracle negative case"))
	legacyScript, err := topics.BuildUHRPScript(legacyHash, "https://legacy-oracle.example.test/z", "text/plain")
	if err != nil {
		t.Fatalf("build legacy script: %v", err)
	}
	legacyOut := runUHRPOracle(t, oraclePath, nodePath, sdkPath, []string{hex.EncodeToString(legacyScript)})
	if !strings.Contains(legacyOut, "THROWS") {
		t.Fatalf("expected the canonical decode to THROW on a LEGACY-format advert (proves the oracle would catch a leak), got:\n%s", legacyOut)
	}
}
