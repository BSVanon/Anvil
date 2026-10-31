package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

func (s *Server) releaseProofRefreshReservation(txid string) {
	s.proofRefreshMu.Lock()
	delete(s.proofRefreshes, txid)
	s.proofRefreshMu.Unlock()
}

// refreshCachedBEEF waits only briefly for an upgrade. The worker has a
// detached deadline so client cancellation cannot abort a cache refresh.
func (s *Server) refreshCachedBEEF(txid string, cached []byte) ([]byte, string, bool) {
	if s.proofFetcher == nil || s.proofRefreshSlots == nil {
		return cached, spv.BEEFSourceCached, false
	}
	if !s.reserveProofRefresh(txid) {
		return cached, spv.BEEFSourceCached, false
	}
	select {
	case s.proofRefreshSlots <- struct{}{}:
	default:
		s.releaseProofRefreshReservation(txid)
		return cached, spv.BEEFSourceCached, false
	}

	resultCh := make(chan beefRefreshResult, 1)
	go func() {
		result := beefRefreshResult{}
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("cached BEEF refresh panicked", "txid", txid, "panic", recovered)
			}
			<-s.proofRefreshSlots
			resultCh <- result
		}()
		fetched, source, err := s.proofFetcher.FetchBEEF(txid)
		if err != nil {
			s.logger.Debug("cached BEEF refresh failed", "txid", txid, "error", err)
			return
		}
		// FetchBEEF is itself bounded by the fetcher's per-request 30 s HTTP timeout.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if !beefSubjectMatches(fetched, txid) {
			return
		}
		if err := s.fetchedBEEFSPVVerified(ctx, fetched); err != nil {
			return
		}
		if !beefSubjectProven(fetched) {
			return
		}
		stored, err := s.cacheBEEF(fetched)
		if err != nil {
			s.logger.Warn("failed to cache refreshed BEEF", "txid", txid, "error", err)
			return
		}
		if stored {
			result = beefRefreshResult{beef: fetched, source: source, subjectProven: true, stored: true}
		}
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

// cacheBEEF serializes cache writes and preserves an existing subject proof.
func (s *Server) cacheBEEF(beef []byte) (stored bool, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			stored = false
			err = fmt.Errorf("cache BEEF panicked: %v", recovered)
		}
	}()
	tx, err := safeParseBEEF(beef)
	if err != nil {
		return false, err
	}
	s.proofRefreshMu.Lock()
	defer s.proofRefreshMu.Unlock()
	if tx.MerklePath == nil {
		if cached, getErr := s.proofStore.GetBEEF(tx.TxID().String()); getErr == nil {
			cachedTx, parseErr := safeParseBEEF(cached)
			if parseErr == nil && cachedTx.MerklePath != nil {
				return false, nil
			}
		}
	}
	if _, err := s.proofStore.StoreBEEF(beef); err != nil {
		return false, err
	}
	return true, nil
}

func safeParseBEEF(beef []byte) (tx *transaction.Transaction, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			tx = nil
			err = fmt.Errorf("BEEF parse panicked: %v", recovered)
		}
	}()
	return transaction.NewTransactionFromBEEF(beef)
}

// beefSubjectProven identifies whether the subject transaction (rather than an
// ancestor) has a merkle path in the envelope.
func beefSubjectProven(beef []byte) bool {
	tx, err := safeParseBEEF(beef)
	return err == nil && tx.MerklePath != nil
}

func beefSubjectMatches(beef []byte, txid string) bool {
	tx, err := safeParseBEEF(beef)
	return err == nil && tx.TxID().String() == strings.ToLower(txid)
}
