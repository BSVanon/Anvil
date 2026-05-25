package federation

import (
	"context"
	"errors"
	"fmt"

	oa "github.com/bsv-blockchain/go-overlay-services/pkg/core/advertiser"
	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/types"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	admintoken "github.com/bsv-blockchain/go-sdk/overlay/admin-token"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"

	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
)

// Advertiser is Anvil's canonical-primitive-based implementation of the
// upstream advertiser.Advertiser interface from
// bsv-blockchain/go-overlay-services/pkg/core/advertiser.
//
// Why not the canonical go-overlay-discovery-services WalletAdvertiser?
// That implementation pulls in go-wallet-toolbox + GORM (postgres/sqlite)
// + a separate HTTP storage service, designed for a multi-process
// operator topology. Anvil is a single binary with LevelDB; that
// architecture doesn't fit. So we implement the same canonical
// INTERFACE (`oa.Advertiser`) using only canonical PRIMITIVES:
//
//   - SHIP/SLAP PushDrop script construction: go-sdk/overlay/admin-token
//   - Transaction funding + signing: go-sdk/wallet.Interface (Anvil's NodeWallet)
//   - Tx propagation: handled by the engine's Submit pipeline
//     (engine.SyncAdvertisements calls Submit on each TaggedBEEF we
//     return; Submit handles broadcaster + topic admission)
//   - Advertisement storage: our own canonical-shaped SHIPStorage/SLAPStorage
//   - BEEF retrieval for revocation: Anvil's anvilstorage.Storage
//
// Robert chose this approach (option 1 in the 2026-05-24 architectural
// fork) after WalletAdvertiser's runtime requirements proved
// incompatible with Anvil's single-binary LevelDB topology.
type Advertiser struct {
	Wallet       wallet.Interface
	HostingURL   string
	SHIPStore    *SHIPStorage
	SLAPStore    *SLAPStorage
	AnvilStorage *anvilstorage.Storage
}

// _ oa.Advertiser = (*Advertiser)(nil) is the compile-time pin that
// breaks the build if go-overlay-services adds a new Advertiser method
// or changes a signature.
var _ oa.Advertiser = (*Advertiser)(nil)

// NewAdvertiser constructs an Anvil federation advertiser.
func NewAdvertiser(w wallet.Interface, hostingURL string, shipStore *SHIPStorage, slapStore *SLAPStorage, anvilStore *anvilstorage.Storage) *Advertiser {
	return &Advertiser{
		Wallet:       w,
		HostingURL:   hostingURL,
		SHIPStore:    shipStore,
		SLAPStore:    slapStore,
		AnvilStorage: anvilStore,
	}
}

// CreateAdvertisements builds one transaction containing a SHIP or SLAP
// PushDrop output for each AdvertisementData entry, wraps in BEEF, and
// returns the TaggedBEEF. The engine's SyncAdvertisements path then
// Submit()s the TaggedBEEF, which feeds tm_ship/tm_slap topic managers
// (which Anvil also hosts) and propagates via the configured
// broadcaster.
//
// Topics in the returned TaggedBEEF are "tm_ship" / "tm_slap" matching
// the canonical engine's expected admission path.
func (a *Advertiser) CreateAdvertisements(adsData []*oa.AdvertisementData) (overlay.TaggedBEEF, error) {
	if a == nil || a.Wallet == nil {
		return overlay.TaggedBEEF{}, errors.New("federation: advertiser: nil wallet")
	}
	if len(adsData) == 0 {
		return overlay.TaggedBEEF{}, errors.New("federation: advertiser: no advertisement data")
	}
	ctx := context.Background()

	pd := admintoken.NewOverlayAdminToken(a.Wallet)
	outputs := make([]wallet.CreateActionOutput, 0, len(adsData))
	topicSet := map[string]struct{}{}
	for i, ad := range adsData {
		if ad == nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: nil ad at index %d", i)
		}
		if ad.Protocol != overlay.ProtocolSHIP && ad.Protocol != overlay.ProtocolSLAP {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: unsupported protocol %q at index %d", ad.Protocol, i)
		}
		lock, err := pd.Lock(ctx, ad.Protocol, a.HostingURL, ad.TopicOrServiceName)
		if err != nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: lock %s/%s: %w", ad.Protocol, ad.TopicOrServiceName, err)
		}
		outputs = append(outputs, wallet.CreateActionOutput{
			LockingScript:     lock.Bytes(),
			Satoshis:          1,
			OutputDescription: fmt.Sprintf("%s advertisement for %s", ad.Protocol, ad.TopicOrServiceName),
		})
		if ad.Protocol == overlay.ProtocolSHIP {
			topicSet["tm_ship"] = struct{}{}
		} else {
			topicSet["tm_slap"] = struct{}{}
		}
	}

	res, err := a.Wallet.CreateAction(ctx, wallet.CreateActionArgs{
		Description: "SHIP/SLAP advertisement issuance",
		Outputs:     outputs,
	}, "")
	if err != nil {
		return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: create action: %w", err)
	}
	if res == nil || len(res.Tx) == 0 {
		return overlay.TaggedBEEF{}, errors.New("federation: advertiser: create action returned no transaction")
	}

	beefBytes, err := encodeBEEF(res.Tx)
	if err != nil {
		return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: encode BEEF: %w", err)
	}

	topics := make([]string, 0, len(topicSet))
	for t := range topicSet {
		topics = append(topics, t)
	}
	return overlay.TaggedBEEF{Beef: beefBytes, Topics: topics}, nil
}

// FindAllAdvertisements returns the advertisements this node has
// published for the given protocol. Filtered to Domain == HostingURL so
// the engine's revocation pass at SyncAdvertisements never tries to
// revoke another operator's ads — we can't spend their outputs.
func (a *Advertiser) FindAllAdvertisements(protocol overlay.Protocol) ([]*oa.Advertisement, error) {
	if a == nil {
		return nil, errors.New("federation: advertiser: nil receiver")
	}
	if a.HostingURL == "" {
		// Single-node operator with no public URL configured; we don't
		// have any of our own ads to find. Return empty slice (not nil)
		// to match canonical wire shape.
		return []*oa.Advertisement{}, nil
	}
	ctx := context.Background()
	domain := a.HostingURL

	switch protocol {
	case overlay.ProtocolSHIP:
		hits, err := a.SHIPStore.FindRecord(ctx, types.SHIPQuery{Domain: &domain})
		if err != nil {
			return nil, fmt.Errorf("federation: advertiser: query ls_ship: %w", err)
		}
		return a.hydrateAdvertisements(ctx, hits, protocol, "tm_ship"), nil
	case overlay.ProtocolSLAP:
		hits, err := a.SLAPStore.FindRecord(ctx, types.SLAPQuery{Domain: &domain})
		if err != nil {
			return nil, fmt.Errorf("federation: advertiser: query ls_slap: %w", err)
		}
		return a.hydrateAdvertisements(ctx, hits, protocol, "tm_slap"), nil
	default:
		return nil, fmt.Errorf("federation: advertiser: unsupported protocol %q", protocol)
	}
}

// RevokeAdvertisements builds one revocation transaction per
// advertisement and returns a merged BEEF the engine can Submit. The
// engine's tm_ship/tm_slap topic manager observes each spend and
// removes the associated record from the SHIP/SLAP index.
//
// Per-tx strategy: go-sdk's wallet.CreateAction decodes InputBEEF as a
// SINGLE valid BEEF envelope (atomic or standard), so concatenating
// multiple ad.Beef buffers — which the canonical WalletAdvertiser does
// — produces malformed input that the wallet either rejects or
// mis-links. We instead make one CreateAction call per ad, then merge
// the resulting transactions into a single BEEF via
// transaction.NewBeefFromTransactions. Each constituent tx is a clean
// 1-input-1-revocation spend and the engine processes them via Submit
// as if they were independent admissions (which they semantically are —
// each spend invalidates one and only one SHIP/SLAP record).
//
// Codex review 18af38d602483289 caught the original concat-BEEF
// implementation. Per-tx is the canonical-safe alternative; trading a
// few extra wallet round-trips for correctness is the right call here,
// since revoke flows are infrequent (operator topic configuration
// changes, not steady-state traffic).
//
// Each Advertisement must have Beef populated (FindAllAdvertisements
// hydrates this). OutputIndex must reference the SHIP/SLAP output
// within the BEEF.
func (a *Advertiser) RevokeAdvertisements(ads []*oa.Advertisement) (overlay.TaggedBEEF, error) {
	if a == nil || a.Wallet == nil {
		return overlay.TaggedBEEF{}, errors.New("federation: advertiser: nil wallet")
	}
	if len(ads) == 0 {
		return overlay.TaggedBEEF{}, errors.New("federation: advertiser: no advertisements to revoke")
	}
	ctx := context.Background()

	revokeTxs := make([]*transaction.Transaction, 0, len(ads))
	topicSet := map[string]struct{}{}
	for i, ad := range ads {
		if ad == nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: nil ad at index %d", i)
		}
		if len(ad.Beef) == 0 {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: ad at index %d missing BEEF", i)
		}
		txid, err := txidFromBEEF(ad.Beef)
		if err != nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: ad %d txid: %w", i, err)
		}
		res, err := a.Wallet.CreateAction(ctx, wallet.CreateActionArgs{
			Description: fmt.Sprintf("revoke %s advertisement %s", ad.Protocol, ad.TopicOrService),
			Inputs: []wallet.CreateActionInput{{
				Outpoint:              transaction.Outpoint{Txid: *txid, Index: ad.OutputIndex},
				InputDescription:      fmt.Sprintf("revoke %s advertisement %s", ad.Protocol, ad.TopicOrService),
				UnlockingScriptLength: revocationUnlockerLen,
			}},
			InputBEEF: ad.Beef, // single ad's BEEF — always a valid envelope
		}, "")
		if err != nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: create revoke action for ad %d (%s/%s): %w", i, ad.Protocol, ad.TopicOrService, err)
		}
		if res == nil || len(res.Tx) == 0 {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: revoke action %d returned no transaction", i)
		}
		tx, err := transaction.NewTransactionFromBytes(res.Tx)
		if err != nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: parse revoke tx %d: %w", i, err)
		}
		revokeTxs = append(revokeTxs, tx)
		if ad.Protocol == overlay.ProtocolSHIP {
			topicSet["tm_ship"] = struct{}{}
		} else if ad.Protocol == overlay.ProtocolSLAP {
			topicSet["tm_slap"] = struct{}{}
		}
	}

	// Merge all revoke transactions into a single BEEF envelope. The
	// canonical engine.Submit pipeline accepts a BEEF that contains
	// multiple admissable transactions; tm_ship/tm_slap topic managers
	// process each spend independently. We build the merged envelope
	// via Beef.MergeTransaction (go-sdk transaction/beef.go:730) — the
	// canonical primitive for assembling a multi-tx BEEF.
	beef, err := transaction.NewBeefFromTransaction(revokeTxs[0])
	if err != nil {
		return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: build initial revoke BEEF: %w", err)
	}
	for i := 1; i < len(revokeTxs); i++ {
		if _, err := beef.MergeTransaction(revokeTxs[i]); err != nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: merge revoke tx %d: %w", i, err)
		}
	}
	beefBytes, err := beef.Bytes()
	if err != nil {
		return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: encode merged revoke BEEF: %w", err)
	}

	topics := make([]string, 0, len(topicSet))
	for t := range topicSet {
		topics = append(topics, t)
	}
	return overlay.TaggedBEEF{Beef: beefBytes, Topics: topics}, nil
}

// ParseAdvertisement decodes a SHIP or SLAP locking script into the
// canonical Advertisement struct. Delegates to go-sdk's
// admin-token.Decode (the canonical PushDrop decoder for overlay admin
// tokens).
func (a *Advertiser) ParseAdvertisement(outputScript *script.Script) (*oa.Advertisement, error) {
	if outputScript == nil || len(*outputScript) == 0 {
		return nil, errors.New("federation: advertiser: empty script")
	}
	decoded := admintoken.Decode(outputScript)
	if decoded == nil {
		return nil, errors.New("federation: advertiser: not an overlay admin token")
	}
	return &oa.Advertisement{
		Protocol:       decoded.Protocol,
		IdentityKey:    decoded.IdentityKey,
		Domain:         decoded.Domain,
		TopicOrService: decoded.TopicOrService,
	}, nil
}

// --- helpers ---------------------------------------------------------

// revocationUnlockerLen reserves space for the worst-case PushDrop
// unlocker signature (DER ECDSA + sighash flag + push opcode). The
// wallet's signAction path overrides this with the actual signed
// unlocker; the reservation just ensures fee calculation has enough
// slack so the tx isn't underfunded.
const revocationUnlockerLen = 73

// hydrateAdvertisements turns a list of canonical UTXOReferences into
// canonical Advertisement entries by fetching each output's BEEF + script
// from anvilstorage and parsing the SHIP/SLAP PushDrop. Skips entries
// that fail to hydrate so the engine sees only valid advertisements.
//
// The fallback path (record present in local SHIP/SLAP store but BEEF
// absent in anvilstorage — typical for migration-era records before
// W-4-B's BEEF-fetch workstream) uses the canonical SHIP/SLAP record
// itself to source TopicOrService + IdentityKey + Domain. This is
// critical because engine.SyncAdvertisements (engine.go:914-918) matches
// "already advertised" by Domain && TopicOrService; without
// TopicOrService populated, every cycle would treat the record as
// missing and re-advertise it, producing duplicate SHIP/SLAP outputs
// on chain. Codex review 18af38d602483289 caught the original
// implementation returning Domain-only fallbacks.
func (a *Advertiser) hydrateAdvertisements(ctx context.Context, refs []types.UTXOReference, protocol overlay.Protocol, topic string) []*oa.Advertisement {
	out := make([]*oa.Advertisement, 0, len(refs))
	for _, ref := range refs {
		ad, err := a.hydrateAdvertisement(ctx, ref, protocol, topic)
		if err != nil || ad == nil {
			continue
		}
		out = append(out, ad)
	}
	return out
}

// loadCanonicalRecord fetches the SHIP or SLAP record for the given
// outpoint from local storage. Used by the BEEF-empty fallback path so
// hydrateAdvertisement can still populate TopicOrService + IdentityKey
// when the on-chain BEEF isn't available locally. Returns ("", "", nil)
// when the record isn't found in our index — the caller treats that as
// an unrecoverable hydration failure.
func (a *Advertiser) loadCanonicalRecord(ctx context.Context, ref types.UTXOReference, protocol overlay.Protocol) (topicOrService, identityKey string, err error) {
	switch protocol {
	case overlay.ProtocolSHIP:
		hits, err := a.SHIPStore.FindRecord(ctx, types.SHIPQuery{Domain: &a.HostingURL})
		if err != nil {
			return "", "", fmt.Errorf("query SHIP fallback: %w", err)
		}
		for _, h := range hits {
			if h.Txid == ref.Txid && h.OutputIndex == ref.OutputIndex {
				rec, err := a.SHIPStore.lookupRecord(ctx, ref.Txid, ref.OutputIndex)
				if err != nil || rec == nil {
					return "", "", err
				}
				return rec.Topic, rec.IdentityKey, nil
			}
		}
	case overlay.ProtocolSLAP:
		hits, err := a.SLAPStore.FindRecord(ctx, types.SLAPQuery{Domain: &a.HostingURL})
		if err != nil {
			return "", "", fmt.Errorf("query SLAP fallback: %w", err)
		}
		for _, h := range hits {
			if h.Txid == ref.Txid && h.OutputIndex == ref.OutputIndex {
				rec, err := a.SLAPStore.lookupRecord(ctx, ref.Txid, ref.OutputIndex)
				if err != nil || rec == nil {
					return "", "", err
				}
				return rec.Service, rec.IdentityKey, nil
			}
		}
	}
	return "", "", nil
}

// hydrateAdvertisement turns a UTXOReference into a full canonical
// Advertisement by fetching the output's BEEF + locking script from
// anvilstorage and ParseAdvertisement-ing the script.
func (a *Advertiser) hydrateAdvertisement(ctx context.Context, ref types.UTXOReference, protocol overlay.Protocol, topic string) (*oa.Advertisement, error) {
	if a.AnvilStorage == nil {
		return nil, errors.New("federation: advertiser: nil anvil storage")
	}
	txidHash, err := chainhash.NewHashFromHex(ref.Txid)
	if err != nil {
		return nil, fmt.Errorf("parse txid: %w", err)
	}
	if ref.OutputIndex < 0 {
		return nil, fmt.Errorf("negative output index %d", ref.OutputIndex)
	}
	outpoint := &transaction.Outpoint{Txid: *txidHash, Index: uint32(ref.OutputIndex)} //#nosec G115 -- negative guarded above; canonical UTXOReference uses int.
	out, err := a.AnvilStorage.FindOutput(ctx, outpoint, &topic, nil, true)
	if err != nil {
		return nil, fmt.Errorf("find output: %w", err)
	}
	if out == nil {
		return nil, errors.New("output not found")
	}
	if out.Beef == nil {
		// BEEF-empty (post-W-4-B migration state) — output is in
		// anvilstorage but its BEEF was never persisted (legacy engine
		// didn't store BEEF after parsing). Recover the canonical
		// fields by reading the local SHIP/SLAP record directly, since
		// engine.SyncAdvertisements (engine.go:914-918) needs Domain
		// AND TopicOrService to recognise the ad as "already exists".
		// Without TopicOrService, the sync pass would create duplicate
		// ads on every cycle. Codex review 18af38d602483289 caught the
		// original implementation returning a TopicOrService-blank
		// stub.
		topicOrService, identityKey, recErr := a.loadCanonicalRecord(ctx, ref, protocol)
		if recErr != nil {
			return nil, fmt.Errorf("load fallback record: %w", recErr)
		}
		if topicOrService == "" {
			// No local record either — skip rather than emitting a
			// partial that would mismatch the engine's filter.
			return nil, errors.New("BEEF empty and no local SHIP/SLAP record")
		}
		return &oa.Advertisement{
			Protocol:       protocol,
			IdentityKey:    identityKey,
			Domain:         a.HostingURL,
			TopicOrService: topicOrService,
			OutputIndex:    outpoint.Index,
			// Beef remains nil — RevokeAdvertisements detects this and
			// surfaces a clear error rather than building an invalid
			// spend transaction.
		}, nil
	}
	beefBytes, err := out.Beef.Bytes()
	if err != nil {
		return nil, fmt.Errorf("serialize output BEEF: %w", err)
	}
	tx := out.Beef.FindTransactionByHash(&outpoint.Txid)
	if tx == nil {
		return nil, errors.New("output tx not in BEEF")
	}
	if int(outpoint.Index) >= len(tx.Outputs) {
		return nil, errors.New("output index out of range")
	}
	lockingScript := tx.Outputs[outpoint.Index].LockingScript
	ad, err := a.ParseAdvertisement(lockingScript)
	if err != nil || ad == nil {
		return nil, fmt.Errorf("parse advertisement: %w", err)
	}
	if ad.Protocol != protocol {
		return nil, fmt.Errorf("protocol mismatch: want %s, got %s", protocol, ad.Protocol)
	}
	ad.Beef = beefBytes
	ad.OutputIndex = outpoint.Index
	return ad, nil
}

// txidFromBEEF extracts the "subject" txid from a BEEF buffer in any
// canonical shape (V1, V2, or AtomicBEEF). Uses transaction.ParseBeef
// (go-sdk transaction/beef.go:238) — the same canonical entry point
// the engine's gasp pipeline uses — so we handle every variant the
// network surfaces to us identically to the upstream client.
//
// For advertisement BEEFs we expect exactly one application transaction
// (the SHIP/SLAP create tx). ParseBeef returns the most-recently-added
// txid as its third return value; that's the spend subject.
func txidFromBEEF(beefBytes []byte) (*chainhash.Hash, error) {
	_, _, txid, err := transaction.ParseBeef(beefBytes)
	if err != nil {
		return nil, fmt.Errorf("parse BEEF: %w", err)
	}
	if txid == nil {
		return nil, errors.New("BEEF contains no subject transaction")
	}
	return txid, nil
}

// encodeBEEF wraps raw tx bytes in a BEEF v1 envelope, matching the
// canonical pattern used by CreateAdvertisements + RevokeAdvertisements.
func encodeBEEF(txBytes []byte) ([]byte, error) {
	tx, err := transaction.NewTransactionFromBytes(txBytes)
	if err != nil {
		return nil, fmt.Errorf("parse tx: %w", err)
	}
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("build BEEF: %w", err)
	}
	return beef.Bytes()
}
