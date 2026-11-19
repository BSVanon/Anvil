// Package hostiletest serves overlay lookup replies for memory-bound tests:
// replies as costly to decode as peerhygiene's caps let through, and replies
// past each cap. Every reply names a marker transaction whose only output is a
// SLAP advertisement for ls_ship naming a host the test picks, so a test can
// see which replies go-sdk's stock lookup stack decoded: the marker's outpoint
// shows up in a resolver's merged answer, and FindCompetentHosts sends its
// ls_ship query to the advertised host.
//
// It is test support: import it only from _test.go files, never from
// production code.
package hostiletest

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

const octetStream = "application/octet-stream"

// piece is lit, written times times in a row.
type piece struct {
	lit   []byte
	times int64
}

// A Reply is one canned /lookup reply. Its body is a list of pieces, some
// repeated many times, so a server can stream a reply of megabytes without
// holding it in memory.
type Reply struct {
	Name        string
	ContentType string
	// Marker is the "txid.0" key of the marker output, which a resolver's
	// merged answer holds when it decoded the reply.
	Marker string
	pieces []piece
}

func (r *Reply) add(lit []byte, times int64) { r.pieces = append(r.pieces, piece{lit, times}) }

// Len is the body's length in bytes.
func (r *Reply) Len() int64 {
	var n int64
	for _, p := range r.pieces {
		n += int64(len(p.lit)) * p.times
	}
	return n
}

// WriteTo writes the body to w.
func (r *Reply) WriteTo(w io.Writer) (int64, error) {
	var written int64
	for _, p := range r.pieces {
		if p.times == 1 {
			n, err := w.Write(p.lit)
			if written += int64(n); err != nil {
				return written, err
			}
			continue
		}
		// Repeat the piece into chunks of about 32 KiB.
		per := max(1, (32<<10)/int64(len(p.lit)))
		chunk := bytes.Repeat(p.lit, int(min(per, p.times)))
		for left := p.times; left > 0; left -= per {
			n, err := w.Write(chunk[:int64(len(p.lit))*min(per, left)])
			if written += int64(n); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// Bytes returns the whole body.
func (r *Reply) Bytes() []byte {
	var b bytes.Buffer
	b.Grow(int(r.Len()))
	_, _ = r.WriteTo(&b)
	return b.Bytes()
}

// Serve answers every request with r, declaring its Content-Length, and
// returns the server's URL and a count of the requests it answered.
func Serve(t testing.TB, r *Reply) (string, *atomic.Int64) {
	t.Helper()
	hits := new(atomic.Int64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, req.Body)
		w.Header().Set("Content-Type", r.ContentType)
		w.Header().Set("Content-Length", strconv.FormatInt(r.Len(), 10))
		_, _ = r.WriteTo(w)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, hits
}

// Canary is a lookup host that answers every query with an empty output list
// and counts the queries for each name it hosts.
type Canary struct {
	url  string
	mu   sync.Mutex
	hits map[string]int
}

// NewCanary starts a canary.
func NewCanary(t testing.TB) *Canary {
	t.Helper()
	c := &Canary{hits: make(map[string]int)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		c.mu.Lock()
		c.hits[strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/"), "/lookup")]++
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"output-list","outputs":[]}`))
	}))
	t.Cleanup(srv.Close)
	c.url = srv.URL
	return c
}

// Host is the host URL to advertise for name. A facilitator queries it at
// Host(name)+"/lookup".
func (c *Canary) Host(name string) string { return c.url + "/" + name }

// Hits is how many queries reached Host(name).
func (c *Canary) Hits(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits[name]
}

// generator is the compressed secp256k1 generator point. go-sdk's PushDrop
// decoder needs a valid public key in front of the advertisement's fields
// and never checks a signature against it.
var generator, _ = hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

// slapAd returns a transaction with no inputs whose one output advertises
// host for ls_ship over SLAP, as go-sdk's admintoken.Decode reads it.
func slapAd(host string) *transaction.Transaction {
	s := &script.Script{}
	_ = s.AppendPushData(generator)
	_ = s.AppendOpcodes(script.OpCHECKSIG)
	for _, field := range []string{"SLAP", string(generator), host, "ls_ship"} {
		_ = s.AppendPushData([]byte(field))
	}
	_ = s.AppendOpcodes(script.Op2DROP, script.Op2DROP)
	return plainTx(0, s)
}

// pushTx returns a transaction with no inputs and one output whose locking
// script pushes n bytes, distinct by id.
func pushTx(id uint32, n int) *transaction.Transaction {
	s := &script.Script{}
	if n > 0 {
		_ = s.AppendPushData(bytes.Repeat([]byte{0xAB}, n))
	}
	return plainTx(id, s)
}

func plainTx(id uint32, s *script.Script) *transaction.Transaction {
	tx := transaction.NewTransaction()
	tx.LockTime = id
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: s, Satoshis: 1})
	return tx
}

// marker is the "txid.0" key a resolver's merged answer gives tx's output.
func marker(tx *transaction.Transaction) string { return tx.TxID().String() + ".0" }

func beefOf(tx *transaction.Transaction) []byte {
	b, err := tx.BEEF()
	if err != nil {
		panic(err) // a transaction with no inputs always serializes
	}
	return b
}
