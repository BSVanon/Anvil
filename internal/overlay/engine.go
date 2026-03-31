// Package overlay implements a generic BRC-22/24 overlay services engine.
//
// The engine is Babbage-compatible: it accepts TaggedBEEF submissions,
// routes them to registered TopicManagers, tracks admitted UTXOs in LevelDB,
// and answers BRC-24 lookup queries via registered LookupServices.
//
// Topic managers are plugins — each implements a simple interface that decides
// which transaction outputs to admit. SHIP, SLAP, UHRP, tokens, and any
// future overlay type are all just topic managers on the same engine.
package overlay

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

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

// LookupService answers queries about admitted UTXOs for a topic.
// This is the BRC-24 query interface.
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
	Txid        string `json:"txid"`
	Vout        int    `json:"vout"`
	Topic       string `json:"topic"`
	OutputScript []byte `json:"outputScript,omitempty"`
	Satoshis    uint64 `json:"satoshis,omitempty"`
	// Metadata stored by the topic manager (opaque to the engine).
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	Spent       bool            `json:"spent,omitempty"`
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

// Engine is the generic BRC-22/24 overlay services engine.
type Engine struct {
	db     *leveldb.DB
	logger *slog.Logger
	mu     sync.RWMutex

	// Registered topic managers: topic name → manager
	topics map[string]TopicManager
	// Registered lookup services: service name → service
	lookups map[string]LookupService
	// Lookup service → which topics it serves (for routing)
	lookupTopics map[string][]string
}

// NewEngine creates an overlay engine backed by LevelDB.
// The db can be shared with the existing Directory if the key prefixes don't collide.
func NewEngine(db *leveldb.DB, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		db:           db,
		logger:       logger,
		topics:       make(map[string]TopicManager),
		lookups:      make(map[string]LookupService),
		lookupTopics: make(map[string][]string),
	}
}

// RegisterTopic adds a topic manager to the engine.
func (e *Engine) RegisterTopic(name string, tm TopicManager) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.topics[name] = tm
	e.logger.Info("overlay topic registered", "topic", name)
}

// RegisterLookup adds a lookup service to the engine.
func (e *Engine) RegisterLookup(name string, ls LookupService, topics []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lookups[name] = ls
	e.lookupTopics[name] = topics
	e.logger.Info("overlay lookup service registered", "service", name, "topics", topics)
}

// Submit processes a transaction submission (BRC-22).
// Routes the transaction to all topic managers listed in topics.
// Accepts both raw transaction bytes and Atomic BEEF format.
// Returns a STEAK with per-topic admittance results.
func (e *Engine) Submit(txData []byte, topics []string) (STEAK, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Parse transaction: try BEEF first, fall back to raw tx bytes.
	tx, err := tryParseBEEFOrRaw(txData)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction: %w", err)
	}
	txid := tx.TxID().String()

	// Normalize: always pass raw tx bytes to topic managers,
	// regardless of whether the submission was BEEF or raw.
	// This ensures topic managers have one consistent format.
	normalizedTxData := tx.Bytes()

	steak := make(STEAK)

	for _, topic := range topics {
		tm, ok := e.topics[topic]
		if !ok {
			continue // unknown topic, skip
		}

		// Find previously-admitted UTXOs that this tx's inputs spend.
		// Returns map: input index → matched admitted output
		spentByInput := e.findSpentUTXOs(tx, topic)

		// Build the previousUTXOs slice for the topic manager,
		// sorted by input index for deterministic ordering.
		inputIndices := make([]int, 0, len(spentByInput))
		for idx := range spentByInput {
			inputIndices = append(inputIndices, idx)
		}
		sort.Ints(inputIndices)
		previousUTXOs := make([]AdmittedOutput, 0, len(inputIndices))
		for _, idx := range inputIndices {
			previousUTXOs = append(previousUTXOs, spentByInput[idx])
		}

		instructions, err := tm.Admit(normalizedTxData, previousUTXOs)
		if err != nil {
			e.logger.Warn("topic manager admission error", "topic", topic, "error", err)
			continue
		}

		if instructions == nil {
			continue
		}

		// Process admissions: store new UTXOs with metadata
		for _, outIdx := range instructions.OutputsToAdmit {
			output := AdmittedOutput{
				Txid:  txid,
				Vout:  outIdx,
				Topic: topic,
			}
			if outIdx < len(tx.Outputs) {
				out := tx.Outputs[outIdx]
				if out.LockingScript != nil {
					output.OutputScript = out.LockingScript.Bytes()
				}
				output.Satoshis = out.Satoshis
			}
			if instructions.OutputMetadata != nil {
				if meta, ok := instructions.OutputMetadata[outIdx]; ok {
					output.Metadata = meta
				}
			}
			if err := e.storeOutput(output); err != nil {
				e.logger.Warn("failed to store admitted output", "topic", topic, "txid", txid[:16], "vout", outIdx, "error", err)
			}
		}

		// Remap both CoinsRemoved and CoinsToRetain from previousUTXOs
		// slice indices back to real transaction input indices (BRC-22 compatible).
		remapToInputIdx := func(prevIdx int) int {
			if prevIdx >= len(previousUTXOs) {
				return -1
			}
			prev := previousUTXOs[prevIdx]
			for inIdx, matched := range spentByInput {
				if matched.Txid == prev.Txid && matched.Vout == prev.Vout {
					return inIdx
				}
			}
			return -1
		}

		realCoinsRemoved := make([]int, 0, len(instructions.CoinsRemoved))
		for _, prevIdx := range instructions.CoinsRemoved {
			if prevIdx < len(previousUTXOs) {
				prev := previousUTXOs[prevIdx]
				e.removeOutput(prev.Txid, prev.Vout, topic)
				e.logger.Debug("overlay output spent and removed",
					"topic", topic, "txid", prev.Txid[:16], "vout", prev.Vout)
			}
			if realIdx := remapToInputIdx(prevIdx); realIdx >= 0 {
				realCoinsRemoved = append(realCoinsRemoved, realIdx)
			}
		}
		instructions.CoinsRemoved = realCoinsRemoved

		realCoinsRetained := make([]int, 0, len(instructions.CoinsToRetain))
		for _, prevIdx := range instructions.CoinsToRetain {
			if realIdx := remapToInputIdx(prevIdx); realIdx >= 0 {
				realCoinsRetained = append(realCoinsRetained, realIdx)
			}
		}
		instructions.CoinsToRetain = realCoinsRetained

		steak[topic] = instructions
	}

	return steak, nil
}

// Lookup answers a BRC-24 query.
func (e *Engine) Lookup(question LookupQuestion) (*LookupAnswer, error) {
	e.mu.RLock()
	ls, ok := e.lookups[question.Service]
	e.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown lookup service: %s", question.Service)
	}

	return ls.Lookup(question.Query)
}

// ListTopics returns all registered topic names.
func (e *Engine) ListTopics() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	names := make([]string, 0, len(e.topics))
	for name := range e.topics {
		names = append(names, name)
	}
	return names
}

// ListLookupServices returns all registered lookup service names.
func (e *Engine) ListLookupServices() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	names := make([]string, 0, len(e.lookups))
	for name := range e.lookups {
		names = append(names, name)
	}
	return names
}

// GetOutputsByTopic returns all admitted (unspent) outputs for a topic.
func (e *Engine) GetOutputsByTopic(topic string) ([]AdmittedOutput, error) {
	prefix := []byte("ovl:" + topic + ":")
	iter := e.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	var outputs []AdmittedOutput
	for iter.Next() {
		var out AdmittedOutput
		if err := json.Unmarshal(iter.Value(), &out); err != nil {
			continue
		}
		if !out.Spent {
			outputs = append(outputs, out)
		}
	}
	return outputs, iter.Error()
}

// --- Reconciliation (Rui's insight: chain is source of truth) ---

// UTXOChecker verifies whether a UTXO is still unspent on-chain.
// Implementations can use WhatsOnChain, a full node, or any UTXO query API.
type UTXOChecker interface {
	IsUnspent(txid string, vout int) (bool, error)
}

// Reconcile compares the local index against the on-chain UTXO set.
// Removes any locally-tracked outputs that have been spent on-chain.
// This makes the overlay self-healing — even if the engine misses a spend
// event, the next reconciliation catches it.
//
// Inspired by Rui Da Silva's insight: the UTXO set IS the state.
// Our LevelDB is just a cache/index. The chain is always correct.
func (e *Engine) Reconcile(checker UTXOChecker) (removed int, checked int, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	prefix := []byte("ovl:")
	iter := e.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	var toDelete [][]byte
	for iter.Next() {
		checked++
		var out AdmittedOutput
		if err := json.Unmarshal(iter.Value(), &out); err != nil {
			continue
		}

		unspent, err := checker.IsUnspent(out.Txid, out.Vout)
		if err != nil {
			// Can't verify — skip, don't delete on uncertainty
			continue
		}

		if !unspent {
			// Chain says it's spent — remove from our index
			key := make([]byte, len(iter.Key()))
			copy(key, iter.Key())
			toDelete = append(toDelete, key)
		}
	}

	for _, key := range toDelete {
		_ = e.db.Delete(key, nil) // best-effort cleanup
		removed++
	}

	if removed > 0 {
		e.logger.Info("overlay reconciliation: removed spent outputs",
			"removed", removed, "checked", checked)
	}

	return removed, checked, iter.Error()
}

// --- Internal storage ---

// Key format: "ovl:<topic>:<txid>:<vout>" → AdmittedOutput JSON
func outputKey(topic, txid string, vout int) []byte {
	return []byte(fmt.Sprintf("ovl:%s:%s:%d", topic, txid, vout))
}

func (e *Engine) storeOutput(out AdmittedOutput) error {
	data, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return e.db.Put(outputKey(out.Topic, out.Txid, out.Vout), data, nil)
}

func (e *Engine) removeOutput(txid string, vout int, topic string) {
	key := outputKey(topic, txid, vout)
	_ = e.db.Delete(key, nil) // best-effort removal
}

// findSpentUTXOs checks if any inputs in the transaction spend previously-admitted UTXOs.
// Returns a map: input index → matched admitted output.
func (e *Engine) findSpentUTXOs(tx *transaction.Transaction, topic string) map[int]AdmittedOutput {
	spent := make(map[int]AdmittedOutput)
	for i, input := range tx.Inputs {
		if input.SourceTXID == nil {
			continue
		}
		prevTxid := input.SourceTXID.String()
		prevVout := int(input.SourceTxOutIndex)
		key := outputKey(topic, prevTxid, prevVout)
		data, err := e.db.Get(key, nil)
		if err != nil {
			continue
		}
		var out AdmittedOutput
		if err := json.Unmarshal(data, &out); err != nil {
			continue
		}
		spent[i] = out
	}
	return spent
}

// tryParseBEEFOrRaw attempts to parse transaction data as Atomic BEEF first,
// falling back to raw transaction bytes.
func tryParseBEEFOrRaw(data []byte) (*transaction.Transaction, error) {
	// Atomic BEEF v1 starts with 0x0100BEEF (little-endian: 0x01 0x00 0xBE 0xEF)
	if len(data) > 4 && data[0] == 0x01 && data[1] == 0x00 && data[2] == 0xBE && data[3] == 0xEF {
		// Try BEEF parsing via go-sdk
		tx, err := transaction.NewTransactionFromBEEF(data)
		if err == nil {
			return tx, nil
		}
		// BEEF parsing failed, try as raw (might be coincidental byte pattern)
	}

	// Try raw transaction bytes
	return transaction.NewTransactionFromBytes(data)
}
