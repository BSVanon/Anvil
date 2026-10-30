package main

import "testing"

func TestTipIsStale(t *testing.T) {
	const (
		now       = int64(10_000)
		threshold = 1800
	)

	if !tipIsStale(now-threshold-1, now, threshold) {
		t.Fatal("tip older than the threshold should be stale")
	}
	if tipIsStale(now-threshold, now, threshold) {
		t.Fatal("tip exactly at the threshold should not be stale")
	}
	if tipIsStale(now-300, now, threshold) {
		t.Fatal("fresh tip should not be stale")
	}
}
