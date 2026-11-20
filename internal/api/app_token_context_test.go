package api

import (
	"net/http/httptest"
	"testing"
)

func TestAppTokenTopicMatchesExactTopicOnly(t *testing.T) {
	req := httptest.NewRequest("GET", "/data?topic=a", nil)
	ctx := withAppTokenTopic(req.Context(), "a")
	req = req.WithContext(ctx)

	if !appTokenTopicMatches(req, "a") {
		t.Fatal("expected a match for the exact validated topic")
	}
	if appTokenTopicMatches(req, "b") {
		t.Fatal("a token validated for topic a must not match topic b")
	}
	if appTokenTopicMatches(req, "a:sub") {
		t.Fatal("a token validated for topic a must not prefix-match a:sub")
	}
	if appTokenTopicMatches(req, "") {
		t.Fatal("an empty topic must never match, even with a validated context value")
	}
}

func TestAppTokenTopicMatchesAbsentContext(t *testing.T) {
	req := httptest.NewRequest("GET", "/data?topic=a", nil)
	if appTokenTopicMatches(req, "a") {
		t.Fatal("a request with no appTokenTopic context value must never match")
	}
}
