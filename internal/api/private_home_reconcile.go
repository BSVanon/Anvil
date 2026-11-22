package api

import (
	"context"
	"errors"
	"time"

	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/BSVanon/Anvil/internal/messaging"
)

func (s *Server) reconcilePrivateHomeAdmissions() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	revocations, err := ReconcilePrivateHomeAdmissions(ctx, s.messagingPolicy.PrivateHomes, s.certificateGate.Gate)
	if err != nil {
		s.logger.Error("private home admission reconciliation failed", "error", err)
	}
	if s.gossipMgr != nil {
		for _, revocation := range revocations {
			s.gossipMgr.BroadcastHomeRevoke(revocation.Member, revocation.BeforeIssuedAt)
		}
	}
}

// ReconcilePrivateHomeAdmissions restores certificate watches and fails closed
// on any binding that cannot be revalidated. Call it before mesh startup so a
// stale persisted claim cannot be synchronized first.
func ReconcilePrivateHomeAdmissions(ctx context.Context, registry *messaging.PrivateHomeStore, gate *certgate.Gate) ([]messaging.PrivateHomeRevocation, error) {
	if registry == nil || gate == nil {
		return nil, nil
	}
	admissions, err := registry.Admissions()
	if err != nil {
		return nil, err
	}
	var revocations []messaging.PrivateHomeRevocation
	var failures []error
	for _, admission := range admissions {
		claim, current, readErr := registry.Current(admission.Member)
		if readErr != nil {
			failures = append(failures, readErr)
			continue
		}
		if !current || claim.IssuedAt != admission.IssuedAt {
			if deleteErr := registry.DeleteAdmission(admission.Member); deleteErr != nil {
				failures = append(failures, deleteErr)
			}
			continue
		}
		restoreErr := gate.RestoreAdmission(ctx, admission.Member, admission.Outpoint)
		if restoreErr == nil {
			continue
		}
		if !errors.Is(restoreErr, certgate.ErrRevoked) {
			failures = append(failures, restoreErr)
		}
		before, changed, revokeErr := registry.RevokeMember(admission.Member)
		if revokeErr != nil {
			failures = append(failures, revokeErr)
			continue
		}
		if changed {
			revocations = append(revocations, messaging.PrivateHomeRevocation{
				Member: admission.Member, BeforeIssuedAt: before,
			})
		}
	}
	return revocations, errors.Join(failures...)
}
