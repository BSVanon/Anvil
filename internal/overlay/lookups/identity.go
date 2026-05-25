package lookups

// Canonical upstream primitive — Identity Lookup Service (ls_identity).
//
// Pragmatic transitional placement: hosted in Anvil today; will be
// re-exported from `bsv-blockchain/go-overlay-discovery-services` once
// that repo gains a topic-impl partition for non-SHIP/SLAP canonical
// primitives. Port source:
// `bsv-blockchain/overlay-express-examples/src/services/identity/IdentityLookupServiceFactory.ts`.
//
// Query support in W-10.1: identityKey, certifierKey, outpoint. The
// attributes-based query (paymail handle resolution) requires keyring
// + public-attribute decryption which is deferred per the identity.go
// admission-side note. SendBSV-Wallet's primary path (resolve by
// identityKey) is fully supported.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	identityItemPrefix      = "lk_identity:item:" // lk_identity:item:<txid>:<vout> → JSON identityRecord
	identityKeyIndexPrefix  = "lk_identity:key:"  // lk_identity:key:<identityKey>:<txid>:<vout> → sentinel
	identityCertIndexPrefix = "lk_identity:crt:"  // lk_identity:crt:<certifierKey>:<txid>:<vout> → sentinel
)

// identityRecord is the per-output state kept in LevelDB. AdmittedAt
// (Unix-nanos) drives most-recent-first ordering when multiple certs
// for the same subject exist (e.g. cert rotation).
type identityRecord struct {
	IdentityKey  string `json:"identity_key"`
	CertifierKey string `json:"certifier_key,omitempty"`
	CertType     string `json:"cert_type,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	AdmittedAt   int64  `json:"admitted_at"`
}

// IdentityLookupService implements engine.LookupService for tm_identity.
type IdentityLookupService struct {
	db   *leveldb.DB
	docs string
	meta *overlay.MetaData
}

// NewIdentityLookupService constructs an Identity lookup against the
// supplied LevelDB handle.
func NewIdentityLookupService(db *leveldb.DB) *IdentityLookupService {
	return &IdentityLookupService{
		db: db,
		docs: "Identity Lookup Service (BRC-52): resolve verifiable identity certificates by " +
			"identityKey (subject pubkey hex), certifierKey (issuer pubkey hex), or outpoint. " +
			"Attribute-based lookup (paymail handle → identity) is a planned follow-up that " +
			"requires keyring extraction support.",
		meta: &overlay.MetaData{
			Name:        topics.IdentityLookupServiceName,
			Description: "BRC-52 verifiable identity certificate resolution",
			Version:     "1.0.0",
		},
	}
}

// Compile-time assertion that the type satisfies engine.LookupService.
var _ engine.LookupService = (*IdentityLookupService)(nil)

// --- event handlers --------------------------------------------------------

// OutputAdmittedByTopic indexes a freshly-admitted identity cert.
func (s *IdentityLookupService) OutputAdmittedByTopic(ctx context.Context, payload *engine.OutputAdmittedByTopic) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.IdentityTopicName {
		return nil
	}
	tx, focusTxid, err := loadFocusTx(payload.AtomicBEEF)
	if err != nil {
		return fmt.Errorf("identity lookup: %w", err)
	}
	if int(payload.OutputIndex) >= len(tx.Outputs) {
		return fmt.Errorf("identity lookup: output index %d out of range for tx %s", payload.OutputIndex, focusTxid.String())
	}
	out := tx.Outputs[payload.OutputIndex]
	if out.LockingScript == nil {
		return nil
	}
	entry, err := topics.ParseIdentityOutput(ctx, out.LockingScript.Bytes())
	if err != nil || entry == nil {
		// Admission already verified the signature; a re-parse miss
		// here is non-fatal.
		return nil
	}
	rec := identityRecord{
		IdentityKey:  strings.ToLower(entry.IdentityKey),
		CertifierKey: strings.ToLower(entry.CertifierKey),
		CertType:     entry.CertType,
		SerialNumber: entry.SerialNumber,
		AdmittedAt:   nowUnixNano(),
	}
	body, err := json.Marshal(&rec)
	if err != nil {
		return fmt.Errorf("identity lookup: marshal record: %w", err)
	}
	batch := new(leveldb.Batch)
	batch.Put(itemKey(identityItemPrefix, focusTxid, payload.OutputIndex), body)
	if rec.IdentityKey != "" {
		batch.Put(identityHashKey(identityKeyIndexPrefix, rec.IdentityKey, focusTxid, payload.OutputIndex), nil)
	}
	if rec.CertifierKey != "" {
		batch.Put(identityHashKey(identityCertIndexPrefix, rec.CertifierKey, focusTxid, payload.OutputIndex), nil)
	}
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("identity lookup: write index: %w", err)
	}
	return nil
}

// OutputSpent removes the record on cert rotation.
func (s *IdentityLookupService) OutputSpent(ctx context.Context, payload *engine.OutputSpent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.IdentityTopicName || payload.Outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&payload.Outpoint.Txid, payload.Outpoint.Index)
}

// OutputNoLongerRetainedInHistory is treated like OutputSpent.
func (s *IdentityLookupService) OutputNoLongerRetainedInHistory(ctx context.Context, outpoint *transaction.Outpoint, topic string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if topic != topics.IdentityTopicName || outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&outpoint.Txid, outpoint.Index)
}

// OutputEvicted removes the record regardless of topic.
func (s *IdentityLookupService) OutputEvicted(ctx context.Context, outpoint *transaction.Outpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&outpoint.Txid, outpoint.Index)
}

// OutputBlockHeightUpdated is a no-op.
func (s *IdentityLookupService) OutputBlockHeightUpdated(ctx context.Context, txid *chainhash.Hash, blockHeight uint32, blockIndex uint64) error {
	return nil
}

// --- query path ------------------------------------------------------------

// Lookup answers an Identity query.
func (s *IdentityLookupService) Lookup(ctx context.Context, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if question == nil {
		return nil, errors.New("identity lookup: nil question")
	}
	if question.Service != topics.IdentityLookupServiceName {
		return nil, fmt.Errorf("identity lookup: service %q not supported", question.Service)
	}
	var q topics.IdentityLookupQuery
	if err := jsonUnmarshalQuery(question.Query, &q); err != nil {
		return nil, fmt.Errorf("identity lookup: %w", err)
	}

	switch {
	case q.IdentityKey != "":
		ops, err := s.findAllByHash(identityKeyIndexPrefix, strings.ToLower(q.IdentityKey), strings.ToLower(q.CertifierKey))
		if err != nil {
			return nil, err
		}
		return formulaList(ops), nil

	case q.CertifierKey != "":
		ops, err := s.findAllByHash(identityCertIndexPrefix, strings.ToLower(q.CertifierKey), "")
		if err != nil {
			return nil, err
		}
		return formulaList(ops), nil

	case q.Outpoint != "":
		op, err := parseOutpointString(q.Outpoint)
		if err != nil {
			return nil, fmt.Errorf("identity lookup: %w", err)
		}
		if _, err := s.db.Get(itemKey(identityItemPrefix, &op.Txid, op.Index), nil); err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				return formulaList(nil), nil
			}
			return nil, fmt.Errorf("identity lookup: probe outpoint: %w", err)
		}
		return formulaList([]*transaction.Outpoint{op}), nil

	case len(q.Attributes) > 0:
		// Attribute-based resolution (paymail handle → identityKey) is
		// DEFERRED to W-11. The canonical TS implementation decrypts
		// publicly-revealed attribute fields via
		// VerifiableCertificate.decryptFields(anyoneWallet), but the
		// on-chain PushDrop wire format publishes a plain Certificate
		// without the verifier-specific keyring needed for that decode.
		// See docs/internal/SENDBSV_USERS_TOPIC_REQUEST.md §
		// "Identity attributes deferral (W-11)" for the resolution
		// plan. Returning an explicit Freeform answer with a deferred
		// flag (rather than silent-empty) so callers know to fall back
		// to the supported identityKey path instead of guessing why
		// the result list is empty.
		return &lookup.LookupAnswer{
			Type:   lookup.AnswerTypeFreeform,
			Result: map[string]interface{}{"deferred": true, "since": "W-10.1", "use": "identityKey"},
		}, nil

	default:
		return nil, errors.New("identity lookup: query must include identityKey, certifierKey, outpoint, or attributes")
	}
}

// GetDocumentation returns the human-readable description.
func (s *IdentityLookupService) GetDocumentation() string { return s.docs }

// GetMetaData returns the canonical metadata block.
func (s *IdentityLookupService) GetMetaData() *overlay.MetaData { return s.meta }

// --- internal helpers ------------------------------------------------------

// findAllByHash returns outpoints matching the given hash, optionally
// filtered to a specific certifier (when filterCertifier is non-empty).
// Most-recent-first ordering by AdmittedAt.
func (s *IdentityLookupService) findAllByHash(prefix, hashHex, filterCertifier string) ([]*transaction.Outpoint, error) {
	fullPrefix := []byte(prefix + hashHex + ":")
	type candidate struct {
		op *transaction.Outpoint
		at int64
	}
	var candidates []candidate
	err := scanPrefix(s.db, fullPrefix, func(key, _ []byte) error {
		op, ok := decodeIdentityHashKey(key, len(fullPrefix))
		if !ok {
			return nil
		}
		body, err := s.db.Get(itemKey(identityItemPrefix, &op.Txid, op.Index), nil)
		if err != nil {
			return nil // index drift — skip
		}
		var rec identityRecord
		if err := json.Unmarshal(body, &rec); err != nil {
			return nil
		}
		if filterCertifier != "" && rec.CertifierKey != filterCertifier {
			return nil
		}
		candidates = append(candidates, candidate{op: op, at: rec.AdmittedAt})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("identity lookup: scan %s: %w", prefix, err)
	}
	// Sort most-recent-first. Stable so equal-timestamp records keep
	// their LevelDB-iteration order (lex-sorted by outpoint).
	for i := 1; i < len(candidates); i++ {
		j := i
		for j > 0 && candidates[j-1].at < candidates[j].at {
			candidates[j-1], candidates[j] = candidates[j], candidates[j-1]
			j--
		}
	}
	out := make([]*transaction.Outpoint, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.op)
	}
	return out, nil
}

// removeOutpoint deletes record + both secondary indexes.
func (s *IdentityLookupService) removeOutpoint(txid *chainhash.Hash, vout uint32) error {
	primary := itemKey(identityItemPrefix, txid, vout)
	body, err := s.db.Get(primary, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("identity lookup: read for remove: %w", err)
	}
	var rec identityRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return s.db.Delete(primary, nil)
	}
	batch := new(leveldb.Batch)
	batch.Delete(primary)
	if rec.IdentityKey != "" {
		batch.Delete(identityHashKey(identityKeyIndexPrefix, rec.IdentityKey, txid, vout))
	}
	if rec.CertifierKey != "" {
		batch.Delete(identityHashKey(identityCertIndexPrefix, rec.CertifierKey, txid, vout))
	}
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("identity lookup: delete batch: %w", err)
	}
	return nil
}

// identityHashKey produces <prefix><hash>:<txid>:<vout>.
func identityHashKey(prefix, hashHex string, txid *chainhash.Hash, vout uint32) []byte {
	return []byte(prefix + hashHex + ":" + txid.String() + ":" + strconv.FormatUint(uint64(vout), 10))
}

// decodeIdentityHashKey extracts the trailing outpoint.
func decodeIdentityHashKey(key []byte, prefixLen int) (*transaction.Outpoint, bool) {
	if len(key) < prefixLen {
		return nil, false
	}
	rest := string(key[prefixLen:])
	idx := strings.LastIndexByte(rest, ':')
	if idx != 64 {
		return nil, false
	}
	h, err := chainhash.NewHashFromHex(rest[:64])
	if err != nil {
		return nil, false
	}
	v, err := strconv.ParseUint(rest[idx+1:], 10, 32)
	if err != nil {
		return nil, false
	}
	return &transaction.Outpoint{Txid: *h, Index: uint32(v)}, true
}
