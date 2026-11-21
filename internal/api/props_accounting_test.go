package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/BSVanon/Anvil/internal/txrelay"
)

func accountingStats(t *testing.T, srv *Server) map[string]interface{} {
	t.Helper()
	w := getWithHeaders(srv, "/stats", map[string]string{"Authorization": "Bearer test-token"})
	if w.Code != http.StatusOK {
		t.Fatalf("stats = %d %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	stats, ok := body["brc121"].(map[string]interface{})
	if !ok {
		t.Fatalf("stats have no BRC-121 accounting: %v", body)
	}
	return stats
}

func TestAccountingPropertyJournalWalletAndStats(t *testing.T) {
	rows := []struct {
		name       string
		configure  func(*brc121Fix, *int)
		wantCodes  []int
		wantWallet int
		wantAccept float64
	}{
		{"accepted", func(f *brc121Fix, calls *int) {
			f.pg.brc121.submit = func(ctx context.Context, p *brc121Payment, sweep bool) (*txrelay.ARCResponse, error) {
				*calls++
				if !f.pg.brc121.journal.has(p.txid.String()) {
					return nil, errors.New("payment reached the network before its journal write")
				}
				return submitBRC121With(ctx, p, sweep, f.arc.send)
			}
		}, []int{http.StatusOK}, 1, 1},
		{"network refused", func(f *brc121Fix, calls *int) {
			f.arc.answer("REJECTED", 0)
			f.pg.brc121.submit = func(ctx context.Context, p *brc121Payment, sweep bool) (*txrelay.ARCResponse, error) {
				*calls++
				if !f.pg.brc121.journal.has(p.txid.String()) {
					return nil, errors.New("payment reached the network before its journal write")
				}
				return submitBRC121With(ctx, p, sweep, f.arc.send)
			}
		}, []int{http.StatusPaymentRequired}, 0, 0},
		{"ambiguous then accepted", func(f *brc121Fix, calls *int) {
			f.pg.brc121.submit = func(_ context.Context, p *brc121Payment, _ bool) (*txrelay.ARCResponse, error) {
				*calls++
				if !f.pg.brc121.journal.has(p.txid.String()) {
					return nil, errors.New("payment reached the network before its journal write")
				}
				if *calls == 1 {
					return nil, errors.New("network reply unavailable")
				}
				return &txrelay.ARCResponse{TxID: p.txid.String(), Status: "SEEN_ON_NETWORK"}, nil
			}
		}, []int{http.StatusServiceUnavailable, http.StatusOK}, 1, 1},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := newBRC121Fix(t, 100)
			srv := testServer(t)
			srv.paymentGate = f.pg
			rebuildRoutes(srv)
			calls := 0
			row.configure(f, &calls)
			headers := f.payment(t, 100, brc121Pay{})
			for i, want := range row.wantCodes {
				w := getWithHeaders(srv, "/status", headers)
				if w.Code != want {
					t.Fatalf("attempt %d = %d %s, want %d", i+1, w.Code, w.Body.String(), want)
				}
			}
			internalizes, held := f.wallet.recorded()
			if internalizes != row.wantWallet || held != row.wantWallet {
				t.Fatalf("wallet internalizes %d, held %d, want %d", internalizes, held, row.wantWallet)
			}
			if f.journaled() != 0 {
				t.Fatalf("terminal outcome left %d payments kept", f.journaled())
			}
			stats := accountingStats(t, srv)
			if stats["accepted"] != row.wantAccept || stats["journaled"] != float64(1) {
				t.Fatalf("accounting stats = %v", stats)
			}
			if calls != len(row.wantCodes) {
				t.Fatalf("network calls = %d, want %d", calls, len(row.wantCodes))
			}
		})
	}
}
