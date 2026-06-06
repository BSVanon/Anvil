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
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
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

	// Identity key for token field[1]. The canonical admission validator
	// (go-overlay-discovery-services IsTokenSignatureCorrectlyLinked) parses
	// this field as the identity and re-derives the expected locking key from
	// it, so it MUST be the same wallet identity pd.Lock derives the locking
	// key from below.
	idRes, err := a.Wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	if err != nil {
		return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: identity key: %w", err)
	}
	if idRes == nil || idRes.PublicKey == nil {
		return overlay.TaggedBEEF{}, errors.New("federation: advertiser: wallet returned no identity key")
	}
	identityKeyBytes := idRes.PublicKey.Compressed()

	// Build SHIP/SLAP tokens with the CANONICAL WalletAdvertiser PushDrop
	// recipe (go-overlay-discovery-services advertiser.CreateAdvertisements):
	// Counterparty=Anyone + forSelf=true. This is NOT the same as go-sdk's
	// admin-token.Lock, which signs with Counterparty=Self + forSelf=false —
	// a recipe the canonical admittance path REJECTS ("Invalid token
	// signature linkage"), so those ads were never admitted, never stored,
	// and re-minted every cycle (the SHIP/SLAP duplicate flood). The admission
	// validator verifies via the anyone-wallet with Counterparty=Other(identity),
	// which only reciprocates the Anyone/forSelf=true derivation. See
	// admission_repro_test.go for the proof.
	pd := pushdrop.PushDrop{Wallet: a.Wallet}
	outputs := make([]wallet.CreateActionOutput, 0, len(adsData))
	topicSet := map[string]struct{}{}
	for i, ad := range adsData {
		if ad == nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: nil ad at index %d", i)
		}
		if ad.Protocol != overlay.ProtocolSHIP && ad.Protocol != overlay.ProtocolSLAP {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: unsupported protocol %q at index %d", ad.Protocol, i)
		}
		protocolID := wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
			Protocol:      string(ad.Protocol.ID()),
		}
		if protocolID.Protocol == "" {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: invalid overlay protocol id %q at index %d", ad.Protocol, i)
		}
		lock, err := pd.Lock(
			ctx,
			[][]byte{
				[]byte(ad.Protocol),
				identityKeyBytes,
				[]byte(a.HostingURL),
				[]byte(ad.TopicOrServiceName),
			},
			protocolID,
			"1",
			wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
			true, // forSelf
			true, // includeSignature
			pushdrop.LockBefore,
		)
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
	pd := pushdrop.PushDrop{Wallet: a.Wallet}
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
		protocolID := wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
			Protocol:      string(ad.Protocol.ID()),
		}
		if protocolID.Protocol == "" {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: invalid overlay protocol id %q at index %d", ad.Protocol, i)
		}
		// The unlocker MUST match the CreateAdvertisements lock recipe
		// (Counterparty=Anyone / forSelf key) or it cannot spend the
		// advertisement output. Guarded by
		// TestRevoke_AnyoneUnlockRecipe_SatisfiesAnyoneLock.
		unlocker := pd.Unlock(
			ctx, protocolID, "1",
			wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
			wallet.SignOutputsAll, false,
		)

		// Phase 1: the wallet builds + funds the spend but cannot itself sign
		// the foreign PushDrop input, so it returns a SignableTransaction.
		res, err := a.Wallet.CreateAction(ctx, wallet.CreateActionArgs{
			Description: fmt.Sprintf("revoke %s advertisement %s", ad.Protocol, ad.TopicOrService),
			Inputs: []wallet.CreateActionInput{{
				Outpoint:              transaction.Outpoint{Txid: *txid, Index: ad.OutputIndex},
				InputDescription:      fmt.Sprintf("revoke %s advertisement %s", ad.Protocol, ad.TopicOrService),
				UnlockingScriptLength: unlocker.EstimateLength(),
			}},
			InputBEEF: ad.Beef, // single ad's BEEF — always a valid envelope
		}, "")
		if err != nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: create revoke action for ad %d (%s/%s): %w", i, ad.Protocol, ad.TopicOrService, err)
		}
		if res == nil || res.SignableTransaction == nil || len(res.SignableTransaction.Tx) == 0 {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: revoke action %d returned no signable transaction", i)
		}

		// Phase 2: find our PushDrop input in the funded tx, sign it with the
		// matching unlocker, and return that unlocking script via SignAction
		// (the wallet signs its own funding inputs).
		_, signableTx, _, err := transaction.ParseBeef(res.SignableTransaction.Tx)
		if err != nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: parse signable revoke tx %d: %w", i, err)
		}
		if signableTx == nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: signable revoke tx %d has no subject tx", i)
		}
		adIdx := -1
		for idx, in := range signableTx.Inputs {
			if in.SourceTXID != nil && in.SourceTXID.IsEqual(txid) && in.SourceTxOutIndex == ad.OutputIndex {
				adIdx = idx
				break
			}
		}
		if adIdx < 0 {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: revoke tx %d missing advertisement input %s:%d", i, txid, ad.OutputIndex)
		}
		unlockingScript, err := unlocker.Sign(signableTx, adIdx)
		if err != nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: sign revoke input %d: %w", i, err)
		}
		signRes, err := a.Wallet.SignAction(ctx, wallet.SignActionArgs{
			Reference: res.SignableTransaction.Reference,
			Spends: map[uint32]wallet.SignActionSpend{
				uint32(adIdx): {UnlockingScript: unlockingScript.Bytes()}, //#nosec G115 -- adIdx is a real input index, never negative here.
			},
		}, "")
		if err != nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: sign revoke action %d: %w", i, err)
		}
		if signRes == nil || len(signRes.Tx) == 0 {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: revoke action %d returned no signed transaction", i)
		}
		// wallet returns Tx as a BEEF envelope (V1/V2/AtomicBEEF); ParseBeef
		// returns the constituent transaction directly.
		_, tx, _, err := transaction.ParseBeef(signRes.Tx)
		if err != nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: parse signed revoke tx %d: %w", i, err)
		}
		if tx == nil {
			return overlay.TaggedBEEF{}, fmt.Errorf("federation: advertiser: signed revoke tx %d has no subject tx", i)
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

// hydrateAdvertisements turns a list of canonical UTXOReferences into
// canonical Advertisement entries, sourcing Domain + TopicOrService from
// each local SHIP/SLAP record (BEEF best-effort). An entry is skipped only
// when no local record exists for it; a BEEF/anvilstorage hydration miss
// never drops it, because engine.SyncAdvertisements (engine.go:914-918)
// matches "already advertised" on Domain && TopicOrService alone — and
// dropping an already-advertised ad makes the sync pass re-mint it every
// cycle. Codex reviews 18af38d602483289 (TopicOrService must be populated)
// and the v3.1.3 flood fix (hydration must not drop indexed ads).
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

// hydrateAdvertisement builds a canonical Advertisement for one of this
// node's SHIP/SLAP records.
//
// CRITICAL: Domain + TopicOrService come from the canonical SHIP/SLAP
// RECORD (loadCanonicalRecord), never from BEEF hydration, and the ad is
// NEVER dropped for an anvilstorage/BEEF failure. engine.SyncAdvertisements
// (engine.go:914-918) matches "already advertised" only on Domain &&
// TopicOrService — both of which live in the record. Dropping an ad
// because its BEEF won't hydrate makes the sync pass treat the topic as
// unadvertised and re-mint it every cycle, which (once admission passes)
// admits + indexes a fresh duplicate set each cycle — the SHIP/SLAP
// duplicate flood. BEEF is attached best-effort below, for the revoke path
// only (RevokeAdvertisements guards on nil BEEF).
func (a *Advertiser) hydrateAdvertisement(ctx context.Context, ref types.UTXOReference, protocol overlay.Protocol, topic string) (*oa.Advertisement, error) {
	if ref.OutputIndex < 0 {
		return nil, fmt.Errorf("negative output index %d", ref.OutputIndex)
	}
	topicOrService, identityKey, err := a.loadCanonicalRecord(ctx, ref, protocol)
	if err != nil {
		return nil, fmt.Errorf("load canonical record: %w", err)
	}
	if topicOrService == "" {
		// No local SHIP/SLAP record for this outpoint — genuinely unknown;
		// skip rather than emit a partial that mismatches the engine filter.
		return nil, errors.New("no local SHIP/SLAP record for outpoint")
	}
	ad := &oa.Advertisement{
		Protocol:       protocol,
		IdentityKey:    identityKey,
		Domain:         a.HostingURL,
		TopicOrService: topicOrService,
		OutputIndex:    uint32(ref.OutputIndex), //#nosec G115 -- negative guarded above; canonical UTXOReference uses int.
	}
	// Best-effort BEEF for RevokeAdvertisements. A hydration miss leaves
	// ad.Beef nil but MUST NOT drop the ad — dedup is already satisfied by
	// Domain + TopicOrService above.
	if a.AnvilStorage != nil {
		if txidHash, herr := chainhash.NewHashFromHex(ref.Txid); herr == nil {
			outpoint := &transaction.Outpoint{Txid: *txidHash, Index: ad.OutputIndex}
			if out, ferr := a.AnvilStorage.FindOutput(ctx, outpoint, &topic, nil, true); ferr == nil && out != nil && out.Beef != nil {
				if beefBytes, berr := out.Beef.Bytes(); berr == nil {
					ad.Beef = beefBytes
				}
			}
		}
	}
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

// encodeBEEF normalizes the wallet's CreateActionResult.Tx into ATOMIC
// BEEF wire format keyed to the advertisement transaction.
//
// wallet-toolbox returns res.Tx in BEEF format (V1, V2, or AtomicBEEF
// depending on the toolbox version and the surrounding CreateAction
// args). canonical ParseBeef handles all three uniformly, and we re-emit
// AtomicBEEF for the subject tx.
//
// Why ATOMIC specifically: engine.Submit passes TaggedBEEF.Beef verbatim
// to lookup services as payload.AtomicBEEF (go-overlay-services
// engine.go:664), and the canonical SHIP/SLAP lookup parses it with
// transaction.NewBeefFromAtomicBytes — which only accepts atomic format.
// Emitting standard BEEF here made admission succeed but the
// post-admission StoreSHIPRecord notification fail ("failed to parse
// atomic BEEF: use NewBeefFromBytes ..."), so ads were admitted on-topic
// but never indexed into ls_ship/ls_slap (and FindAllAdvertisements,
// which reads that index, kept returning empty → re-mint). Guarded by
// TestAdvertiser_CreateAdvertisements_ProducesAdmittableTokens, which
// asserts the output parses as AtomicBEEF.
//
// v3.0.0 originally called NewTransactionFromBytes on res.Tx, which
// works for raw tx bytes but mis-parses a BEEF header (read the BEEF
// magic as a tx version + input count, then decoded a downstream
// script-length varint as ~941 KB). v3.0.1 fixes this.
func encodeBEEF(walletTx []byte) ([]byte, error) {
	beef, _, txid, err := transaction.ParseBeef(walletTx)
	if err != nil {
		return nil, fmt.Errorf("parse wallet BEEF: %w", err)
	}
	if beef == nil || txid == nil {
		return nil, errors.New("wallet returned empty BEEF")
	}
	return beef.AtomicBytes(txid)
}
