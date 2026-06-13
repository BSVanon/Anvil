package legacyshim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// TestStatusForSubmitError pins the HTTP status mapping: client-input faults are
// 4xx (so a topic-name mismatch reads as a clear 400 instead of a node-outage
// 500), the cap timeout is 504, and everything else stays 500.
func TestStatusForSubmitError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"unknown topic", engine.ErrUnknownTopic, http.StatusBadRequest},
		{"wrapped unknown topic", fmt.Errorf("submit: %w", engine.ErrUnknownTopic), http.StatusBadRequest},
		{"invalid beef", engine.ErrInvalidBeef, http.StatusUnprocessableEntity},
		{"invalid transaction", engine.ErrInvalidTransaction, http.StatusUnprocessableEntity},
		{"deadline exceeded", context.DeadlineExceeded, http.StatusGatewayTimeout},
		{"generic", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := statusForSubmitError(c.err); got != c.want {
				t.Fatalf("statusForSubmitError(%v) = %d, want %d", c.err, got, c.want)
			}
		})
	}
}
