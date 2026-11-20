package api

import (
	"net/http/httptest"
	"testing"
)

// TestPaidTopicMatchesExactTopicOnly mirrors
// TestAppTokenTopicMatchesExactTopicOnly (app_token_context_test.go) for the
// payment side of the same rule: a verified payment covers exactly the
// topic it was resolved and charged against (resolvePayees,
// payment_resolve.go) — never a prefix, never a different topic. A
// mutation that loosened paidTopicMatches to prefix matching would let a
// cheap toll paid on a parent topic unredact a sibling or child topic's own,
// separately-priced payload (cold review RISK 4).
func TestPaidTopicMatchesExactTopicOnly(t *testing.T) {
	req := httptest.NewRequest("GET", "/data?topic=a", nil)
	ctx := withPaidTopic(req.Context(), "a")
	req = req.WithContext(ctx)

	if !paidTopicMatches(req, "a") {
		t.Fatal("expected a match for the exact topic the payment was charged against")
	}
	if paidTopicMatches(req, "a:premium") {
		t.Fatal("a payment charged against topic a must not prefix-match a:premium")
	}
	if paidTopicMatches(req, "b") {
		t.Fatal("a payment charged against topic a must not match an unrelated topic b")
	}
	if paidTopicMatches(req, "") {
		t.Fatal("an empty topic must never match, even with a recorded paid-topic context value")
	}
}

// TestPaidTopicMatchesAbsentContext: a request that never went through a
// verified payment (no withPaidTopic call) must never match any topic.
func TestPaidTopicMatchesAbsentContext(t *testing.T) {
	req := httptest.NewRequest("GET", "/data?topic=a", nil)
	if paidTopicMatches(req, "a") {
		t.Fatal("a request with no paid-topic context value must never match")
	}
}
