package wallet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/defs"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/storage"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/wallet"
)

// NodeWallet wraps go-wallet-toolbox's Wallet with Anvil's infrastructure.
type NodeWallet struct {
	inner   *wallet.Wallet
	logger  *slog.Logger
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

	return &NodeWallet{inner: w, logger: logger}, nil
}

// Close shuts down the wallet.
func (nw *NodeWallet) Close() {
	nw.inner.Close()
}

// RegisterRoutes adds wallet REST endpoints to the given mux.
// All wallet endpoints require authentication (caller adds middleware).
func (nw *NodeWallet) RegisterRoutes(mux *http.ServeMux, requireAuth func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /wallet/outputs", requireAuth(nw.handleListOutputs))
	mux.HandleFunc("POST /wallet/create-action", requireAuth(nw.handleCreateAction))
	mux.HandleFunc("POST /wallet/sign-action", requireAuth(nw.handleSignAction))
	mux.HandleFunc("POST /wallet/internalize", requireAuth(nw.handleInternalize))
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

