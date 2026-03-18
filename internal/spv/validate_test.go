package spv

import (
	"context"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// gullibleTracker always says yes — for testing BEEF parsing without
// needing real headers.
type gullibleTracker struct{}

func (g *gullibleTracker) IsValidRootForHeight(_ context.Context, _ *chainhash.Hash, _ uint32) (bool, error) {
	return true, nil
}

func (g *gullibleTracker) CurrentHeight(_ context.Context) (uint32, error) {
	return 999999, nil
}

// rejectTracker always says no — for testing proof rejection.
type rejectTracker struct{}

func (r *rejectTracker) IsValidRootForHeight(_ context.Context, _ *chainhash.Hash, _ uint32) (bool, error) {
	return false, nil
}

func (r *rejectTracker) CurrentHeight(_ context.Context) (uint32, error) {
	return 999999, nil
}

func TestValidateBEEFInvalidBytes(t *testing.T) {
	v := NewValidator(&gullibleTracker{})
	result, err := v.ValidateBEEF(context.Background(), []byte("not a beef"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatal("expected invalid for garbage bytes")
	}
	if result.Message == "" {
		t.Fatal("expected error message")
	}
}

func TestValidateBEEFNilInput(t *testing.T) {
	v := NewValidator(&gullibleTracker{})
	result, err := v.ValidateBEEF(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatal("expected invalid for nil input")
	}
}

func TestValidateBeefFullInvalidBytes(t *testing.T) {
	v := NewValidator(&gullibleTracker{})
	result, err := v.ValidateBeefFull(context.Background(), []byte("not beef"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatal("expected invalid for garbage bytes")
	}
}

func TestNewValidatorCreation(t *testing.T) {
	v := NewValidator(&gullibleTracker{})
	if v == nil {
		t.Fatal("expected non-nil validator")
	}
	if v.tracker == nil {
		t.Fatal("expected non-nil tracker")
	}
}
