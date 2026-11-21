package api

import (
	"context"

	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

func newBRC121Stub() (*brc121ARC, *txrelay.ARCClient) {
	return &brc121ARC{status: "SEEN_ON_NETWORK"}, txrelay.NewARCClient("http://unused.invalid", "")
}

func (a *brc121ARC) send(ctx context.Context, raw []byte) (*txrelay.ARCResponse, error) {
	a.calls.Add(1)
	a.mu.Lock()
	a.bodies = append(a.bodies, append([]byte{}, raw...))
	status, code, hold := a.status, a.httpCode, a.hold
	a.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if code != 0 {
		return nil, &txrelay.ARCHTTPError{StatusCode: code, Body: `{"title":"refused"}`}
	}
	tx, err := transaction.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, err
	}
	return &txrelay.ARCResponse{TxID: tx.TxID().String(), Status: status}, nil
}
