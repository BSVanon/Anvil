package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/defs"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/storage"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/wallet"
)

// NodeWallet wraps go-wallet-toolbox's Wallet with Anvil's infrastructure.
type NodeWallet struct {
	inner     *wallet.Wallet
	validator *spv.Validator
	logger    *slog.Logger
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

	// Create SQLite storage provider via GORM
	storageProvider, err := storage.NewGORMProvider(
		defs.NetworkMainnet,
		services,
		storage.WithConfig(storage.ProviderConfig{
			DBConfig: defs.Database{
				Engine: defs.DBTypeSQLite,
				SQLite: defs.SQLite{
					ConnectionString: dataDir + "/wallet.db",
				},
			},
		}),
		storage.WithBeefVerifier(storage.NewDefaultBeefVerifier(services)),
	)
	if err != nil {
		return nil, fmt.Errorf("create wallet storage: %w", err)
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

	validator := spv.NewValidator(headerStore)
	return &NodeWallet{inner: w, validator: validator, logger: logger}, nil
}

// Close shuts down the wallet.
func (nw *NodeWallet) Close() {
	nw.inner.Close()
}

// RegisterRoutes adds wallet REST endpoints to the given mux.
// All wallet endpoints require authentication (caller adds middleware).
func (nw *NodeWallet) RegisterRoutes(mux *http.ServeMux, requireAuth func(http.HandlerFunc) http.HandlerFunc) {
	// App-facing endpoints (per ARCHITECTURE.md)
	mux.HandleFunc("POST /wallet/invoice", requireAuth(nw.handleInvoice))
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
// Returns the derived P2PKH address and derivation context so the payer
// can construct a BEEF payment to that address.
func (nw *NodeWallet) handleInvoice(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	var req struct {
		Counterparty string `json:"counterparty"` // hex pubkey of the payer
		Description  string `json:"description"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid JSON: %v", err)})
		return
	}

	// Derive a payment-specific public key via go-wallet-toolbox
	// using BRC-29 payment protocol with the counterparty
	protocolID := sdk.Protocol{
		SecurityLevel: sdk.SecurityLevelEveryApp,
		Protocol:      "invoice payment",
	}
	keyResult, err := nw.inner.GetPublicKey(r.Context(), sdk.GetPublicKeyArgs{
		EncryptionArgs: sdk.EncryptionArgs{
			ProtocolID: protocolID,
			KeyID:      "1",
			Counterparty: sdk.Counterparty{
				Type: sdk.CounterpartyTypeOther,
			},
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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"address":     addr.AddressString,
		"public_key":  hex.EncodeToString(keyResult.PublicKey.Compressed()),
		"description": req.Description,
	})
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

