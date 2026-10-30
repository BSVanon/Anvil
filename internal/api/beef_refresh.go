package api

import (
	"context"
	"errors"
	"time"

	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

const (
	proofRefreshInterval = time.Minute
	maxProofRefreshes    = 10000
)

var proofRefreshWait = 3 * time.Second

var errBEEFInvalidConfidence = errors.New("invalid BEEF confidence")

type beefRefreshResult struct {
	beef          []byte
	source        string
	subjectProven bool
	stored        bool
}

// reserveProofRefresh grants one refresh attempt per transaction per interval.
// It first reclaims expired reservations; if all entries are live, it evicts
// the oldest one because this map is only an anti-stampede optimization.
func (s *Server) reserveProofRefresh(txid string) bool {
	now := time.Now()
	s.proofRefreshMu.Lock()
	defer s.proofRefreshMu.Unlock()
	if last, ok := s.proofRefreshes[txid]; ok && now.Sub(last) < proofRefreshInterval {
		return false
	}
	if len(s.proofRefreshes) >= maxProofRefreshes {
		for id, attempted := range s.proofRefreshes {
			if attempted.Before(now.Add(-proofRefreshInterval)) {
				delete(s.proofRefreshes, id)
			}
		}
		if len(s.proofRefreshes) >= maxProofRefreshes {
			var oldestID string
			var oldest time.Time
			for id, attempted := range s.proofRefreshes {
				if oldestID == "" || attempted.Before(oldest) {
					oldestID, oldest = id, attempted
				}
			}
			delete(s.proofRefreshes, oldestID)
		}
	}
	s.proofRefreshes[txid] = now
	return true
}

// refreshCachedBEEF waits only briefly for an upgrade. The worker has a
// detached deadline so client cancellation cannot abort a cache refresh.
func (s *Server) refreshCachedBEEF(txid string, cached []byte) ([]byte, string, bool) {
	if s.proofFetcher == nil || !s.reserveProofRefresh(txid) {
		return cached, spv.BEEFSourceCached, false
	}

	resultCh := make(chan beefRefreshResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		fetched, source, err := s.proofFetcher.FetchBEEF(txid)
		if err != nil {
			s.logger.Debug("cached BEEF refresh failed", "txid", txid, "error", err)
			resultCh <- beefRefreshResult{}
			return
		}
		if err := s.fetchedBEEFSPVVerified(ctx, fetched); err != nil {
			resultCh <- beefRefreshResult{}
			return
		}
		if !beefSubjectProven(fetched) {
			resultCh <- beefRefreshResult{}
			return
		}
		if _, err := s.proofStore.StoreBEEF(fetched); err != nil {
			s.logger.Warn("failed to cache refreshed BEEF", "txid", txid, "error", err)
			resultCh <- beefRefreshResult{}
			return
		}
		resultCh <- beefRefreshResult{beef: fetched, source: source, subjectProven: true, stored: true}
	}()

	select {
	case result := <-resultCh:
		if result.stored {
			return result.beef, result.source, result.subjectProven
		}
	case <-time.After(proofRefreshWait):
	}
	return cached, spv.BEEFSourceCached, false
}

// fetchedBEEFVerified applies the cache-miss validation policy. A nil
// validator is retained for the existing test/degraded configuration behavior;
// otherwise only a non-invalid local validation result may be served or stored.
func (s *Server) fetchedBEEFVerified(ctx context.Context, beef []byte) error {
	if s.validator == nil {
		return nil
	}
	result, err := s.validator.ValidateBEEF(ctx, beef)
	if err != nil {
		s.logger.Warn("fetched BEEF validation error", "error", err)
		return err
	}
	if result.Confidence == spv.ConfidenceInvalid {
		s.logger.Warn("fetched BEEF invalid confidence", "message", result.Message)
		return errBEEFInvalidConfidence
	}
	return nil
}

func beefValidationErrorMessage(err error) string {
	if errors.Is(err, errBEEFInvalidConfidence) {
		return "fetched proof failed local header verification"
	}
	return "fetched proof failed local validation"
}

// fetchedBEEFSPVVerified is deliberately stricter than the cache-miss policy:
// an old unproven cache entry is only upgraded after a fully locally verified
// proof is available.
func (s *Server) fetchedBEEFSPVVerified(ctx context.Context, beef []byte) error {
	if s.validator == nil {
		return errBEEFInvalidConfidence
	}
	result, err := s.validator.ValidateBEEF(ctx, beef)
	if err != nil {
		s.logger.Warn("refreshed BEEF validation error", "error", err)
		return err
	}
	if result.Confidence != spv.ConfidenceSPVVerified {
		s.logger.Warn("refreshed BEEF was not SPV verified", "confidence", result.Confidence, "message", result.Message)
		return errBEEFInvalidConfidence
	}
	return nil
}

// beefSubjectProven identifies whether the subject transaction (rather than an
// ancestor) has a merkle path in the envelope.
func beefSubjectProven(beef []byte) bool {
	tx, err := transaction.NewTransactionFromBEEF(beef)
	return err == nil && tx.MerklePath != nil
}
