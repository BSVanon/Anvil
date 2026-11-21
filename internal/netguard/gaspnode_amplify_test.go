package netguard

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// gaspAmplifyPad is how many '<' bytes pad the field under test in
// TestGuard_ReEncodeDoesNotAmplifyAPaddedField: large enough that the old
// json.Marshal re-encode (HTML-escaping '<' to "<", 6 bytes each, cold
// review would have been unmistakable against the
// relative bound below, while staying fast for a suite run.
const gaspAmplifyPad = 2_000_000

// gaspAmplifyHeapRatio and gaspAmplifyHeapSlack bound the guarded heap peak
// relative to the unguarded one: guarded <= unguarded*gaspAmplifyHeapRatio +
// gaspAmplifyHeapSlack. 1.25x plus 16 MiB of slack is generous over the
// guard's own extra cost (one decode into a gasp.Node, discarded once
// decodeGASPNode's consumed-bytes slice is taken -- see checkGASPNode's doc
// comment) and far under the roughly 6x a re-encode of an HTML-escaped field
// used to cost.
const (
	gaspAmplifyHeapRatio = 1.25
	gaspAmplifyHeapSlack = 16 << 20
)

// gaspAmplifyReply builds a /requestForeignGASPNode reply that is otherwise
// honest except for one field padded with n raw, UNESCAPED '<' bytes: valid
// JSON (escaping '<' is never required by the spec), so this is what the
// reply actually costs a peer to send -- one byte per '<', not the 6-byte
// "<" json.Marshal would produce if this string were re-encoded.
// json.Marshal HTML-escapes '<', '>' and '&' on the way out, so re-encoding
// a decoded copy of this field, rather than handing on the bytes decoded,
// used to multiply the reply's size on the way out even though it cost the
// peer nothing extra to send. "rawTx"
// pads RawTx itself with non-hex junk instead of a valid transaction --
// gaspNodeMalformed's hex.DecodeString step lets a non-hex RawTx through
// unchecked, the same as a Proof skips the check entirely. rawTx carries
// honestTx's hex unless field is itself "rawTx". Built by hand, not via
// gasp.Node + json.Marshal, specifically so the wire bytes stay in this raw,
// cheap-to-send form instead of round-tripping through the same escaping
// this test needs to catch.
func gaspAmplifyReply(t *testing.T, field string, n int) []byte {
	t.Helper()
	return gaspAmplifyReplyWithTx(t, honestTx(t), field, n)
}

// gaspAmplifyReplyWithTx is gaspAmplifyReply with the caller's own raw
// transaction bytes, hex-encoded into RawTx unless field is "rawTx".
func gaspAmplifyReplyWithTx(t *testing.T, rawTx []byte, field string, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(`{"graphID":"` + gaspOutpoint.String() + `","outputIndex":0`)
	if field != "rawTx" {
		b.WriteString(`,"rawTx":"` + hex.EncodeToString(rawTx) + `"`)
	}
	switch field {
	case "txMetadata", "outputMetadata", "proof", "rawTx":
	default:
		t.Fatalf("gaspAmplifyReply: unknown field %q", field)
	}
	b.WriteString(`,"` + field + `":"`)
	b.Write(bytes.Repeat([]byte{'<'}, n))
	b.WriteString(`"}`)
	return b.Bytes()
}

// gaspAmplifyHeapPeak serves reply once and measures RequestNode's heap peak
// through cl.
func gaspAmplifyHeapPeak(t *testing.T, reply []byte, cl *http.Client) (peak, base uint64) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(reply)))
		_, _ = w.Write(reply)
	}))
	defer srv.Close()
	var err error
	peak, base = hostiletest.HeapPeak(func() {
		_, err = engine.NewOverlayGASPRemote(srv.URL, "tm_x", cl, 8).RequestNode(context.Background(), nil, gaspOutpoint, false)
	})
	if err != nil {
		t.Fatalf("RequestNode: %v", err)
	}
	return peak, base
}

// TestGuard_ReEncodeDoesNotAmplifyAPaddedField is a permanent regression:
// checkGASPNode
// used to hand an honest, checked node on by re-encoding it with
// json.Marshal, which HTML-escapes '<', '>' and '&' into 6-byte sequences --
// so any field a hostile peer pads with those characters (metadata, a proof,
// which skips the check entirely, or even a non-hex RawTx, which the hex
// step lets through) re-encoded up to 6x larger, for about 2 GiB of heap on
// one cap-sized reply, free for any peer at boot. Handing on the bytes
// decodeGASPNode actually consumed, instead of a re-encoding (see
// checkGASPNode), closes this: guarded cost now tracks unguarded cost within
// a small, fixed overhead, for every field a reply can pad.
func TestGuard_ReEncodeDoesNotAmplifyAPaddedField(t *testing.T) {
	for _, field := range []string{"txMetadata", "outputMetadata", "proof", "rawTx"} {
		t.Run(field, func(t *testing.T) {
			reply := gaspAmplifyReply(t, field, gaspAmplifyPad)
			unguardedPeak, unguardedBase := gaspAmplifyHeapPeak(t, reply, &http.Client{})
			guardedPeak, guardedBase := gaspAmplifyHeapPeak(t, reply, http.DefaultClient)
			bound := uint64(float64(unguardedPeak)*gaspAmplifyHeapRatio) + gaspAmplifyHeapSlack
			t.Logf("field=%-14s reply %d bytes: unguarded peak %.1f MiB over %.1f MiB base; guarded peak %.1f MiB over %.1f MiB base; bound %.1f MiB",
				field, len(reply), mib(unguardedPeak), mib(unguardedBase), mib(guardedPeak), mib(guardedBase), mib(bound))
			if guardedPeak > bound {
				t.Errorf("field=%s: guarded heap peak %d bytes is over the %d-byte bound (unguarded peak x%.2f + %d)",
					field, guardedPeak, bound, gaspAmplifyHeapRatio, gaspAmplifyHeapSlack)
			}
		})
	}

	// The amplification fix (handing on the bytes decodeGASPNode consumed,
	// not a re-encoding) must not reopen the original trailing-byte
	// gap. A trailing byte alone is not an error -- doNodeRequest's own
	// Decode tolerates it too -- so this pads a reply that also carries the
	// malformed-script shape (gaspNodeMalformed's actual refusal) and
	// confirms it is still caught, exactly as
	// TestGuard_RefusesEveryTrailingByteVariant's unpadded cases already
	// are, even with a metadata field escaped and a trailing byte both
	// present on the same reply.
	t.Run("trailing byte still refused", func(t *testing.T) {
		reply := append(gaspAmplifyReplyWithTx(t, malformedReparseTx(t), "txMetadata", 1000), 'x')
		url, hits := serveAnswer(t, "application/json", reply, false)
		_, err := engine.NewOverlayGASPRemote(url, "tm_test", http.DefaultClient, 8).
			RequestNode(context.Background(), nil, gaspOutpoint, false)
		if err == nil || !strings.Contains(err.Error(), "undecodable instruction") {
			t.Fatalf("want the malformed script refused, got: %v", err)
		}
		if got := hits.Load(); got != 1 {
			t.Fatalf("expected one request to the peer, got %d", got)
		}
	})
}
