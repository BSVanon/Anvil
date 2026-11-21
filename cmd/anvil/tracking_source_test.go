package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/gateway"
	"github.com/BSVanon/Anvil/internal/ordtrack"
	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
)

// proofMap is a proof store holding the BEEFs it is given.
type proofMap map[string][]byte

func (p proofMap) GetBEEF(txid string) ([]byte, error) {
	if b, ok := p[txid]; ok {
		return b, nil
	}
	return nil, errors.New("not found")
}

// A transaction counts as mined only with a merkle path the node's own
// headers confirm, wherever the path came from.
func TestTrackSourceCountsOnlyProvenMined(t *testing.T) {
	w, chain, other := ordtracktest.NewWallet(t), ordtracktest.NewChain(), ordtracktest.NewChain()
	store := ordtracktest.NewStore()
	stored, fetched, forged, unmined, unknown := w.Fund(ordtracktest.Out{Sats: 1}), w.Fund(ordtracktest.Out{Sats: 2}),
		w.Fund(ordtracktest.Out{Sats: 3}), w.Fund(ordtracktest.Out{Sats: 4}), w.Fund(ordtracktest.Out{Sats: 5})
	chain.Mine(stored, fetched)
	other.Mine(forged) // a path to a block these headers do not hold
	store.Add(stored, fetched, forged, unmined)
	proofs := proofMap{stored.TxID().String(): ordtracktest.AtomicBEEF(t, stored), forged.TxID().String(): ordtracktest.AtomicBEEF(t, forged)}
	fetcher := &chainFetcher{store: store, beef: map[string][]byte{}}
	src := &trackSource{
		proofs: proofs, fetcher: fetcher, headers: chain,
		rawTx: func(ctx context.Context, txid string) ([]byte, error) {
			tx, err := store.Tx(ctx, txid)
			if err != nil {
				return nil, err
			}
			return tx.Bytes(), nil
		},
	}
	ctx := context.Background()
	for _, c := range []struct {
		name  string
		txid  string
		want  ordtrack.Status
		proof bool
	}{
		{"proven by the proof store", stored.TxID().String(), ordtrack.Status{Known: true, Mined: true, Height: stored.MerklePath.BlockHeight}, true},
		{"proven by a fetched proof", fetched.TxID().String(), ordtrack.Status{Known: true, Mined: true, Height: fetched.MerklePath.BlockHeight}, true},
		{"a path these headers do not confirm", forged.TxID().String(), ordtrack.Status{Known: true}, false},
		{"not yet mined", unmined.TxID().String(), ordtrack.Status{Known: true}, false},
		{"unknown", unknown.TxID().String(), ordtrack.Status{}, false},
	} {
		st, err := src.Status(ctx, c.txid)
		if err != nil || st != c.want {
			t.Fatalf("%s: status %+v %v, want %+v", c.name, st, err, c.want)
		}
		if c.txid == unknown.TxID().String() {
			continue
		}
		tx, err := src.Tx(ctx, c.txid)
		if err != nil || tx.TxID().String() != c.txid || (tx.MerklePath != nil) != c.proof {
			t.Fatalf("%s: tx %v, path %v", c.name, err, tx != nil && tx.MerklePath != nil)
		}
	}

	// A fetched proof of another transaction, or none at all, proves nothing.
	fetcher.beef[forged.TxID().String()] = ordtracktest.AtomicBEEF(t, stored)
	if st, _ := src.Status(ctx, forged.TxID().String()); st.Mined {
		t.Fatal("another transaction's proof counted")
	}
	fetcher.beef[forged.TxID().String()] = []byte("not a BEEF")
	if st, _ := src.Status(ctx, forged.TxID().String()); st.Mined {
		t.Fatal("a broken proof counted")
	}
	// Without a tx-status path, a status is an error; a transaction is
	// still fetched, as an unmined one.
	fetcher.err = errors.New("upstream down")
	if _, err := src.Status(ctx, unmined.TxID().String()); err == nil {
		t.Fatal("a failed status lookup reported a status")
	}
	if tx, err := src.Tx(ctx, fetched.TxID().String()); err != nil || tx.MerklePath != nil {
		t.Fatalf("with the status path down: %v, path %v", err, tx != nil && tx.MerklePath != nil)
	}
}

// The follower reads the policy again when the sites file changes and
// every trackedRefreshEvery, and passes the configured origins first.
func TestPolicyFollowerReadsThePolicyAgain(t *testing.T) {
	a, b, conf := fmt.Sprintf("%064x_0", 1), fmt.Sprintf("%064x_1", 2), fmt.Sprintf("%064x_0", 3)
	path := filepath.Join(t.TempDir(), "sites.conf")
	write := func(body string, at time.Time) {
		if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	write("origin "+a+"\n", start.Add(-time.Hour))
	allow := gateway.NewAllowlist(path, "", slog.Default())
	var got [][]string
	f := &policyFollower{
		set:   func(o []string) { got = append(got, o) },
		allow: allow, policy: gateway.NewPolicy(allow, gateway.NewResolver(gateway.ResolverConfig{})),
		configured: []string{conf}, max: 10,
	}
	ctx := context.Background()
	steps := []struct {
		at      time.Time
		edit    string
		stepped bool
		want    string
	}{
		{start, "", true, fmt.Sprint([]string{conf, a})},
		{start.Add(time.Second), "", false, ""},
		{start.Add(2 * time.Second), "origin " + a + "\norigin " + b + "\n", true, fmt.Sprint([]string{conf, a, b})},
		{start.Add(3 * time.Second), "", false, ""},
		{start.Add(2*time.Second + trackedRefreshEvery), "", true, fmt.Sprint([]string{conf, a, b})},
		{start.Add(2*time.Second + trackedRefreshEvery + time.Second), "origin " + b + "\n", true, fmt.Sprint([]string{conf, b})},
	}
	for i, s := range steps {
		if s.edit != "" {
			write(s.edit, start.Add(time.Duration(i)*time.Minute))
			allow.Reload()
		}
		if stepped := f.step(ctx, s.at); stepped != s.stepped {
			t.Fatalf("step %d: stepped %v", i, stepped)
		}
		if s.stepped && fmt.Sprint(got[len(got)-1]) != s.want {
			t.Fatalf("step %d: set %v, want %s", i, got[len(got)-1], s.want)
		}
	}
	if len(f.configured) != 1 {
		t.Fatal("the configured origins were changed")
	}
}
