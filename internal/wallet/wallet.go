package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/defs"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/storage"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/wallet"
	"github.com/syndtr/goleveldb/leveldb"
)

// Invoice is the stored state for a created invoice, keyed by ID.
type Invoice struct {
	ID          string `json:"id"`
	Address     string `json:"address"`
	PublicKey   string `json:"public_key"`
	Description string `json:"description"`
	Counterparty string `json:"counterparty"`
	Protocol    string `json:"protocol"`
	KeyID       string `json:"key_id"`
}

// NodeWallet wraps go-wallet-toolbox's Wallet with Anvil's infrastructure.
type NodeWallet struct {
	inner     *wallet.Wallet
	validator *spv.Validator
	logger    *slog.Logger

	invoiceDB *leveldb.DB // persistent invoice storage
	invoiceMu sync.RWMutex
	nextID    int // monotonic invoice counter, recovered from DB on startup
}

// New creates a new NodeWallet from a WIF key, backed by SQLite storage
// and connected to Anvil's header store for SPV verification.
func New(
	wif string,
	dataDir string,
	headerStore *headers.Store,
	proofStore *spv.ProofStore,
	broadcaster *txrelay.Broadcaster,
	logger *slog.Logger,
) (*NodeWallet, error) {
	services := NewAnvilServices(headerStore, proofStore, broadcaster)

	// Create SQLite storage provider via GORM.
	// Use WithDBConfig (not WithConfig) to preserve default FeeModel/Commission.
	storageProvider, err := storage.NewGORMProvider(
		defs.NetworkMainnet,
		services,
		storage.WithDBConfig(defs.Database{
			Engine: defs.DBTypeSQLite,
			SQLite: defs.SQLite{
				ConnectionString: dataDir + "/wallet.db",
			},
		}),
		storage.WithBeefVerifier(storage.NewDefaultBeefVerifier(services)),
	)
	if err != nil {
		return nil, fmt.Errorf("create wallet storage: %w", err)
	}

	// Derive identity key from WIF for storage migration
	identityKey, err := ec.PrivateKeyFromWif(wif)
	if err != nil {
		return nil, fmt.Errorf("parse identity WIF: %w", err)
	}
	storageIdentityKey := hex.EncodeToString(identityKey.PubKey().Compressed())

	// Migrate the storage schema (creates tables + saves settings).
	// This must happen before wallet.New so that MakeAvailable succeeds.
	if _, err := storageProvider.Migrate(context.Background(), "anvil", storageIdentityKey); err != nil {
		return nil, fmt.Errorf("migrate wallet storage: %w", err)
	}

	w, err := wallet.New(
		defs.NetworkMainnet,
		wallet.WIF(wif),
		storageProvider,
		wallet.WithServices(services),
		wallet.WithLogger(logger),
	)
	if err != nil {
		return nil, fmt.Errorf("create wallet: %w", err)
	}

	// Open persistent invoice store
	invoiceDB, err := leveldb.OpenFile(dataDir+"/invoices", nil)
	if err != nil {
		return nil, fmt.Errorf("open invoice store: %w", err)
	}

	// Recover next invoice ID from existing keys
	maxID := 0
	iter := invoiceDB.NewIterator(nil, nil)
	for iter.Next() {
		if id, err := strconv.Atoi(string(iter.Key())); err == nil && id > maxID {
			maxID = id
		}
	}
	iter.Release()

	validator := spv.NewValidator(headerStore)
	return &NodeWallet{
		inner:     w,
		validator: validator,
		logger:    logger,
		invoiceDB: invoiceDB,
		nextID:    maxID,
	}, nil
}

// Wallet returns the underlying wallet.Interface for use by other subsystems
// (e.g. gossip mesh auth). The caller must not close it — NodeWallet owns the lifecycle.
func (nw *NodeWallet) Wallet() sdk.Interface {
	return nw.inner
}

// Close shuts down the wallet and invoice store.
func (nw *NodeWallet) Close() {
	nw.inner.Close()
	if nw.invoiceDB != nil {
		nw.invoiceDB.Close()
	}
}

// saveInvoice persists an invoice to LevelDB.
func (nw *NodeWallet) saveInvoice(inv *Invoice) error {
	data, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	return nw.invoiceDB.Put([]byte(inv.ID), data, nil)
}

// loadInvoice loads an invoice from LevelDB by ID.
func (nw *NodeWallet) loadInvoice(id string) (*Invoice, error) {
	data, err := nw.invoiceDB.Get([]byte(id), nil)
	if err != nil {
		return nil, err
	}
	var inv Invoice
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

// RegisterRoutes adds wallet REST endpoints to the given mux.
// All wallet endpoints require authentication (caller adds middleware).
func (nw *NodeWallet) RegisterRoutes(mux *http.ServeMux, requireAuth func(http.HandlerFunc) http.HandlerFunc) {
	// App-facing endpoints (per ARCHITECTURE.md)
	mux.HandleFunc("POST /wallet/invoice", requireAuth(nw.handleInvoice))
	mux.HandleFunc("GET /wallet/invoice/{id}", requireAuth(nw.handleGetInvoice))
	mux.HandleFunc("POST /wallet/send", requireAuth(nw.handleSend))
	mux.HandleFunc("POST /wallet/internalize", requireAuth(nw.handleInternalize))
	mux.HandleFunc("GET /wallet/outputs", requireAuth(nw.handleListOutputs))

	// Low-level toolbox endpoints (for advanced use)
	mux.HandleFunc("POST /wallet/create-action", requireAuth(nw.handleCreateAction))
	mux.HandleFunc("POST /wallet/sign-action", requireAuth(nw.handleSignAction))
}

// --- Handlers ---

func (nw *NodeWallet) handleListOutputs(w http.ResponseWriter, r *http.Request) {
	basket := r.URL.Query().Get("basket")
	args := sdk.ListOutputsArgs{
		Basket: basket,
	}

	result, err := nw.inner.ListOutputs(r.Context(), args, "anvil")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleInvoice derives a BRC-42 payment address for a counterparty.
// POST /wallet/invoice
// Body: {"counterparty": "<pubkey_hex>", "description": "..."}
//
// If counterparty is provided, it must be a compressed pubkey hex (33 bytes).
// If omitted, the derivation uses CounterpartyTypeAnyone (BRC-23 convention:
// pubkey = 1*G, the generator point), producing a non-counterparty-specific key.
//
// Returns the invoice ID, derived P2PKH address, and derivation context so
// the payer can construct a BEEF payment to that address.
func (nw *NodeWallet) handleInvoice(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	var req struct {
		Counterparty string `json:"counterparty"` // hex pubkey of the payer (optional)
		Description  string `json:"description"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid JSON: %v", err)})
		return
	}

	// Build counterparty: if a pubkey is provided, use it; otherwise use "anyone"
	counterparty := sdk.Counterparty{Type: sdk.CounterpartyTypeAnyone}
	if req.Counterparty != "" {
		cpBytes, err := hex.DecodeString(req.Counterparty)
		if err != nil || len(cpBytes) != 33 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "counterparty must be 33-byte compressed pubkey hex"})
			return
		}
		cpKey, err := ec.PublicKeyFromBytes(cpBytes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid counterparty pubkey: %v", err)})
			return
		}
		counterparty = sdk.Counterparty{
			Type:         sdk.CounterpartyTypeOther,
			Counterparty: cpKey,
		}
	}

	// Allocate an invoice ID and a per-invoice KeyID so each invoice
	// derives a unique address even for the same counterparty.
	nw.invoiceMu.Lock()
	nw.nextID++
	invoiceID := strconv.Itoa(nw.nextID)
	nw.invoiceMu.Unlock()

	protocolID := sdk.Protocol{
		SecurityLevel: sdk.SecurityLevelEveryApp,
		Protocol:      "invoice payment",
	}
	keyResult, err := nw.inner.GetPublicKey(r.Context(), sdk.GetPublicKeyArgs{
		EncryptionArgs: sdk.EncryptionArgs{
			ProtocolID:   protocolID,
			KeyID:        invoiceID,
			Counterparty: counterparty,
		},
	}, "anvil")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("derive key: %v", err)})
		return
	}

	// Generate P2PKH address from the derived public key
	addr, err := script.NewAddressFromPublicKey(keyResult.PublicKey, true)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("generate address: %v", err)})
		return
	}

	// Persist the invoice to LevelDB so GET /wallet/invoice/:id survives restarts
	inv := &Invoice{
		ID:           invoiceID,
		Address:      addr.AddressString,
		PublicKey:    hex.EncodeToString(keyResult.PublicKey.Compressed()),
		Description:  req.Description,
		Counterparty: req.Counterparty,
		Protocol:     "invoice payment",
		KeyID:        invoiceID,
	}
	if err := nw.saveInvoice(inv); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("persist invoice: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":          invoiceID,
		"address":     inv.Address,
		"public_key":  inv.PublicKey,
		"description": inv.Description,
	})
}

// handleGetInvoice checks whether an invoice has been paid.
// GET /wallet/invoice/:id
//
// Queries the wallet's ListOutputs to find outputs matching the invoice's
// derived address. If a matching output exists, the invoice is considered paid.
func (nw *NodeWallet) handleGetInvoice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invoice id required"})
		return
	}

	inv, err := nw.loadInvoice(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invoice not found"})
		return
	}

	// Query the wallet for outputs — check if any match this invoice's locking script.
	result, err := nw.inner.ListOutputs(r.Context(), sdk.ListOutputsArgs{
		Basket: "default",
	}, "anvil")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("list outputs: %v", err)})
		return
	}

	// Build the expected locking script from the invoice's derived pubkey
	var expectedScript []byte
	if inv.PublicKey != "" {
		if pkBytes, err := hex.DecodeString(inv.PublicKey); err == nil {
			if pk, err := ec.PublicKeyFromBytes(pkBytes); err == nil {
				if invAddr, err := script.NewAddressFromPublicKey(pk, true); err == nil {
					if ls, err := p2pkh.Lock(invAddr); err == nil {
						expectedScript = []byte(*ls)
					}
				}
			}
		}
	}

	paid := false
	var paidTxID string
	var paidAmount uint64
	for _, out := range result.Outputs {
		// Match by locking script (most reliable)
		if expectedScript != nil && fmt.Sprintf("%x", out.LockingScript) == fmt.Sprintf("%x", expectedScript) {
			paid = true
			paidTxID = out.Outpoint.Txid.String()
			paidAmount = out.Satoshis
			break
		}
		// Fallback: match by custom instructions containing the address
		if out.CustomInstructions == inv.Address {
			paid = true
			paidTxID = out.Outpoint.Txid.String()
			paidAmount = out.Satoshis
			break
		}
	}

	resp := map[string]interface{}{
		"id":          inv.ID,
		"address":     inv.Address,
		"description": inv.Description,
		"paid":        paid,
	}
	if paid {
		resp["txid"] = paidTxID
		resp["amount"] = paidAmount
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSend builds and signs a payment transaction.
// POST /wallet/send
// Body: {"to": "<address>", "satoshis": <amount>, "description": "..."}
//
// Uses go-wallet-toolbox's CreateAction + SignAction to build, sign,
// and add the tx to the local mempool. Note: P2P peer relay is not
// yet implemented — the tx is only in the local mempool until that
// is wired.
func (nw *NodeWallet) handleSend(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	var req struct {
		To          string `json:"to"`          // destination address
		Satoshis    uint64 `json:"satoshis"`    // amount
		Description string `json:"description"` // tx description
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid JSON: %v", err)})
		return
	}
	if req.To == "" || req.Satoshis == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to and satoshis required"})
		return
	}

	// Build P2PKH locking script for the destination address using go-sdk
	addr, err := script.NewAddressFromString(req.To)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid address: %v", err)})
		return
	}
	lockingScript, err := p2pkh.Lock(addr)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("build script: %v", err)})
		return
	}

	// CreateAction via go-wallet-toolbox — handles UTXO selection + change
	createResult, err := nw.inner.CreateAction(r.Context(), sdk.CreateActionArgs{
		Description: req.Description,
		Outputs: []sdk.CreateActionOutput{
			{
				LockingScript: []byte(*lockingScript),
				Satoshis:      req.Satoshis,
			},
		},
	}, "anvil")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("create action: %v", err)})
		return
	}

	// If the wallet returned a signable transaction, sign it
	if createResult.SignableTransaction != nil {
		signResult, err := nw.inner.SignAction(r.Context(), sdk.SignActionArgs{
			Reference: createResult.SignableTransaction.Reference,
		}, "anvil")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("sign action: %v", err)})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"txid":     signResult.Txid.String(),
			"satoshis": req.Satoshis,
			"to":       req.To,
			"note":     "tx added to local mempool; P2P peer relay not yet implemented",
		})
		return
	}

	// If no signing needed (already complete)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"txid":     createResult.Txid.String(),
		"satoshis": req.Satoshis,
		"to":       req.To,
		"note":     "tx added to local mempool; P2P peer relay not yet implemented",
	})
}

func (nw *NodeWallet) handleCreateAction(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	var args sdk.CreateActionArgs
	if err := json.Unmarshal(body, &args); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid JSON: %v", err)})
		return
	}

	result, err := nw.inner.CreateAction(r.Context(), args, "anvil")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (nw *NodeWallet) handleSignAction(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	var args sdk.SignActionArgs
	if err := json.Unmarshal(body, &args); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid JSON: %v", err)})
		return
	}

	result, err := nw.inner.SignAction(r.Context(), args, "anvil")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (nw *NodeWallet) handleInternalize(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	var args sdk.InternalizeActionArgs
	if err := json.Unmarshal(body, &args); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid JSON: %v", err)})
		return
	}

	// SPV gate: validate BEEF before internalization.
	// Per architecture: "BEEF validated by our SPV layer first"
	if len(args.Tx) > 0 {
		result, err := nw.validator.ValidateBEEF(context.Background(), args.Tx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("SPV validation error: %v", err)})
			return
		}
		if result.Confidence == spv.ConfidenceInvalid {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{
				"error":      "BEEF failed SPV validation",
				"confidence": result.Confidence,
				"message":    result.Message,
			})
			return
		}
		nw.logger.Info("internalize: BEEF validated",
			"txid", result.TxID,
			"confidence", result.Confidence,
		)
	}

	result, err := nw.inner.InternalizeAction(context.Background(), args, "anvil")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

