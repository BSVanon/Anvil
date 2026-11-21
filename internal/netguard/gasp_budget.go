package netguard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"golang.org/x/sync/semaphore"
)

const (
	// GASPReadPermits bounds replies being buffered or held for SDK decode.
	GASPReadPermits = 4
	// GASPResponseExpansion reserves the raw JSON, its decoded strings, hex
	// bytes, and transaction parse together.
	GASPResponseExpansion int64 = 4
	// GASPResponseMemoryBudget admits one response at the 64 MiB wire cap and
	// several ordinary responses without allowing eight cap-sized buffers.
	GASPResponseMemoryBudget int64 = 384 << 20
)

var (
	gaspReads  = bodyread.NewPermits(GASPReadPermits)
	gaspMemory = semaphore.NewWeighted(GASPResponseMemoryBudget)
)

func acquireGASPReply(resp *http.Response, maxBytes int64) (func(), error) {
	ctx := context.Background()
	if resp != nil && resp.Request != nil {
		ctx = resp.Request.Context()
	}
	releaseRead, err := gaspReads.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("netguard: waiting for a GASP read permit: %w", err)
	}
	if maxBytes <= 0 {
		maxBytes = MaxResponseBytes
	}
	n := maxBytes
	if resp != nil && resp.ContentLength >= 0 && resp.ContentLength < n {
		n = resp.ContentLength
	}
	weight := n * GASPResponseExpansion
	if weight > GASPResponseMemoryBudget {
		releaseRead()
		return nil, fmt.Errorf("netguard: GASP response reservation %d exceeds memory budget", weight)
	}
	if err := gaspMemory.Acquire(ctx, weight); err != nil {
		releaseRead()
		return nil, fmt.Errorf("netguard: waiting for GASP response memory: %w", err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			gaspMemory.Release(weight)
			releaseRead()
		})
	}, nil
}

type heldGASPBody struct {
	r       *bytes.Reader
	release func()
}

func (b *heldGASPBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err == io.EOF {
		b.release()
	}
	return n, err
}

func (b *heldGASPBody) Close() error {
	b.release()
	return nil
}

func newHeldGASPBody(body []byte, release func()) io.ReadCloser {
	return &heldGASPBody{r: bytes.NewReader(body), release: release}
}
