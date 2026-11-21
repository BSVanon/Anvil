package certgate

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

func assertRejectedHintKeepsAdmission(t *testing.T, admissionOutpoint, hintOutpoint, spendingTxid string, verify func(context.Context, string, string) error) {
	t.Helper()
	f := newCertFixture(t)
	op, err := transaction.OutpointFromString(admissionOutpoint)
	if err != nil {
		t.Fatal(err)
	}
	w := newFakeWatcher()
	gate := f.gate(t, w, nil)
	if err := gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, f.subject.PubKey(), op)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	gate.SetSpendVerifier(func(ctx context.Context, outpoint, txid string) error {
		defer close(done)
		return verify(ctx, outpoint, txid)
	})
	w.callback(hintOutpoint, spendingTxid)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("spend hint verification did not finish")
	}
	identity := hex.EncodeToString(f.subject.PubKey().Compressed())
	if !gate.Admitted(t.Context(), identity) {
		t.Fatal("rejected spend hint revoked an admission")
	}
}

type propertyTransactionSource struct {
	txs map[string]*transaction.Transaction
	err error
}

func (s propertyTransactionSource) Tx(_ context.Context, txid string) (*transaction.Transaction, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.txs[txid], nil
}

func propertySpend(lock script.Script) (*transaction.Transaction, *transaction.Transaction) {
	source := transaction.NewTransaction()
	source.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: &lock})
	spend := transaction.NewTransaction()
	spend.AddInput(&transaction.TransactionInput{
		SourceTXID: source.TxID(), SourceTxOutIndex: 0,
		UnlockingScript: &script.Script{}, SequenceNumber: transaction.DefaultSequenceNumber,
	})
	spend.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: &script.Script{script.OpTRUE}})
	return source, spend
}

func TestSpendHintRevokesOnlyAfterScriptVerification(t *testing.T) {
	source, spend := propertySpend(script.Script{script.OpTRUE})
	outpoint := (&transaction.Outpoint{Txid: *source.TxID(), Index: 0}).String()
	txs := map[string]*transaction.Transaction{source.TxID().String(): source, spend.TxID().String(): spend}
	verify := SpendVerifier(propertyTransactionSource{txs: txs})
	if err := verify(t.Context(), outpoint, spend.TxID().String()); err != nil {
		t.Fatalf("verified spend was refused: %v", err)
	}

	t.Run("transaction does not spend outpoint", func(t *testing.T) {
		otherSource, otherSpend := propertySpend(script.Script{script.OpTRUE, script.OpNOP})
		all := map[string]*transaction.Transaction{
			source.TxID().String(): source, otherSource.TxID().String(): otherSource,
			otherSpend.TxID().String(): otherSpend,
		}
		unrelated := SpendVerifier(propertyTransactionSource{txs: all})
		if unrelated(t.Context(), outpoint, otherSpend.TxID().String()) == nil {
			t.Fatal("unrelated spend hint verified")
		}
		assertRejectedHintKeepsAdmission(t, outpoint, outpoint, otherSpend.TxID().String(), unrelated)
	})

	t.Run("input script fails", func(t *testing.T) {
		locked, invalidSpend := propertySpend(script.Script{script.OpFALSE})
		lockedOutpoint := (&transaction.Outpoint{Txid: *locked.TxID(), Index: 0}).String()
		all := map[string]*transaction.Transaction{locked.TxID().String(): locked, invalidSpend.TxID().String(): invalidSpend}
		invalidScript := SpendVerifier(propertyTransactionSource{txs: all})
		if invalidScript(t.Context(), lockedOutpoint, invalidSpend.TxID().String()) == nil {
			t.Fatal("invalid input script verified")
		}
		assertRejectedHintKeepsAdmission(t, lockedOutpoint, lockedOutpoint, invalidSpend.TxID().String(), invalidScript)
	})

	t.Run("hint names different outpoint", func(t *testing.T) {
		different := (&transaction.Outpoint{Txid: *source.TxID(), Index: 1}).String()
		if verify(t.Context(), different, spend.TxID().String()) == nil {
			t.Fatal("different outpoint hint verified")
		}
		assertRejectedHintKeepsAdmission(t, outpoint, different, spend.TxID().String(), verify)
	})

	t.Run("transaction cannot be fetched", func(t *testing.T) {
		unavailable := SpendVerifier(propertyTransactionSource{err: errors.New("unavailable")})
		if unavailable(t.Context(), outpoint, spend.TxID().String()) == nil {
			t.Fatal("unfetched transaction verified")
		}
		assertRejectedHintKeepsAdmission(t, outpoint, outpoint, spend.TxID().String(), unavailable)
	})
}
