// Package overlay holds the shared types and interfaces that Anvil's
// topic managers + legacy compatibility shim depend on. The legacy
// in-process Engine + Submit/Lookup/HTTP handlers were removed in W-7
// (2026-05-16); production now uses the canonical v3 engine wired via
// internal/overlay/v3engine + internal/overlay/legacyshim with storage
// in internal/overlay/storage and lookup services in
// internal/overlay/lookups.
//
// What remains in this file is the Anvil-local TopicManager /
// LookupService interfaces + AdmittanceInstructions / AdmittedOutput /
// STEAK / TaggedBEEF / LookupQuestion / LookupAnswer types. These are
// kept because:
//
//   - Anvil's topic implementations (internal/overlay/topics/*.go)
//     declare conformance against the local TopicManager interface,
//     and the v3 adapter at topics/adapter.go wraps that interface to
//     satisfy the canonical engine.TopicManager.
//   - AdmittedOutput + AdmittanceInstructions are returned by Admit
//     and consumed by the v3 adapter's position→vin remapping logic.
//   - The legacy shim re-uses the JSON wire shapes (STEAK,
//     TaggedBEEF, LookupQuestion, LookupAnswer) to preserve byte-for-
//     byte compatibility with apps that haven't migrated to canonical
//     /submit + /lookup yet (Lens 2 = 2c indefinite).
//
// If a future workstream rewrites the topic implementations to depend
// on the canonical engine.TopicManager directly (no adapter), this
// file can shrink to just AdmittedOutput + AdmittanceInstructions for
// the topic-internal contract.
package overlay

import "encoding/json"

// TopicManager decides which transaction outputs are relevant to a topic.
// This is the BRC-22 admission interface — Babbage-compatible.
//
// Topic names follow BRC-87 convention: "tm_ship", "tm_slap", "tm_uhrp", etc.
type TopicManager interface {
	// Admit evaluates a transaction and returns which outputs to admit
	// and which spent inputs to retain or remove.
	//
	// txData contains the raw transaction bytes.
	// previousUTXOs lists any previously-admitted UTXOs that this tx spends.
	Admit(txData []byte, previousUTXOs []AdmittedOutput) (*AdmittanceInstructions, error)

	// GetDocumentation returns a human-readable description of this topic.
	GetDocumentation() string

	// GetMetadata returns machine-readable metadata about this topic.
	GetMetadata() map[string]interface{}
}

// LookupService answers queries about admitted UTXOs for a topic. The
// legacy in-process implementation that backed this interface has been
// removed; the interface itself remains because legacy *_lookup.go
// files still declare conformance for backward source-compat. Apps now
// receive lookup responses via the canonical engine + the legacy shim
// at /overlay/query.
type LookupService interface {
	// Lookup answers a query and returns matching admitted outputs.
	Lookup(query json.RawMessage) (*LookupAnswer, error)

	// GetDocumentation returns a human-readable description of this service.
	GetDocumentation() string

	// GetMetadata returns machine-readable metadata about this service.
	GetMetadata() map[string]interface{}
}

// AdmittanceInstructions tells the engine what to do with a transaction's outputs.
// Babbage-compatible: same fields as the TypeScript STEAK format.
type AdmittanceInstructions struct {
	// OutputsToAdmit are output indices to add to this topic's UTXO set.
	OutputsToAdmit []int `json:"outputsToAdmit"`
	// CoinsToRetain are input indices that spend previously-admitted UTXOs
	// which should be kept for historical record.
	CoinsToRetain []int `json:"coinsToRetain"`
	// CoinsRemoved are input indices that spend previously-admitted UTXOs
	// which are now removed from the active set.
	CoinsRemoved []int `json:"coinsRemoved,omitempty"`
	// OutputMetadata holds per-output metadata from the topic manager.
	// Keyed by output index. Stored alongside the admitted output for lookup.
	OutputMetadata map[int]json.RawMessage `json:"-"`
}

// STEAK is the per-topic result of a submission.
// Babbage-compatible: maps topic name → admittance instructions.
type STEAK map[string]*AdmittanceInstructions

// TaggedBEEF is a transaction with its target topics.
// Babbage-compatible format for POST /submit.
type TaggedBEEF struct {
	BEEF   []byte   `json:"beef"`
	Topics []string `json:"topics"`
}

// AdmittedOutput represents a UTXO tracked by the engine for a specific topic.
type AdmittedOutput struct {
	Txid         string `json:"txid"`
	Vout         int    `json:"vout"`
	Topic        string `json:"topic"`
	OutputScript []byte `json:"outputScript,omitempty"`
	Satoshis     uint64 `json:"satoshis,omitempty"`
	// Metadata stored by the topic manager (opaque to the engine).
	Metadata json.RawMessage `json:"metadata,omitempty"`
	Spent    bool            `json:"spent,omitempty"`
}

// LookupQuestion is the BRC-24 query format.
type LookupQuestion struct {
	Service string          `json:"service"`
	Query   json.RawMessage `json:"query"`
}

// LookupAnswer is the BRC-24 response format.
type LookupAnswer struct {
	Type    string           `json:"type"` // "output-list", "freeform"
	Outputs []AdmittedOutput `json:"outputs,omitempty"`
	Result  interface{}      `json:"result,omitempty"` // for freeform responses
}
