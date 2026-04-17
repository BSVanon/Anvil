package txrelay

import (
	"log/slog"
	"testing"
	"time"
)

// TestUpstreamStatusNoARCConfigured verifies that a broadcaster without ARC
// reports "down" — it cannot forward to miners, so wallet consumers should
// failover to another federation node.
func TestUpstreamStatusNoARCConfigured(t *testing.T) {
	b := NewBroadcaster(NewMempool(), nil, slog.Default())
	if got := b.UpstreamStatus(); got != UpstreamDown {
		t.Errorf("expected %q when ARC not configured, got %q", UpstreamDown, got)
	}
}

// TestUpstreamStatusInitialConfiguredState verifies that a freshly-configured
// broadcaster (ARC set, no activity yet) reports "healthy". Federation nodes
// with zero broadcast traffic should not be flagged unreachable.
func TestUpstreamStatusInitialConfiguredState(t *testing.T) {
	b := NewBroadcaster(NewMempool(), NewARCClient("https://arc.example.com", ""), slog.Default())
	if got := b.UpstreamStatus(); got != UpstreamHealthy {
		t.Errorf("expected %q for freshly-configured ARC, got %q", UpstreamHealthy, got)
	}
}

// TestUpstreamStatusRecentSuccess verifies "healthy" when last success was
// within the 5-minute window.
func TestUpstreamStatusRecentSuccess(t *testing.T) {
	b := NewBroadcaster(NewMempool(), NewARCClient("https://arc.example.com", ""), slog.Default())
	b.arcLastSuccess.Store(time.Now().Unix() - 30)
	if got := b.UpstreamStatus(); got != UpstreamHealthy {
		t.Errorf("expected %q for recent success, got %q", UpstreamHealthy, got)
	}
}

// TestUpstreamStatusDegradedAge verifies that a success 5-30 minutes old is
// reported as "degraded" — ARC was working but hasn't been exercised recently.
func TestUpstreamStatusDegradedAge(t *testing.T) {
	b := NewBroadcaster(NewMempool(), NewARCClient("https://arc.example.com", ""), slog.Default())
	b.arcLastSuccess.Store(time.Now().Unix() - 600) // 10 min ago
	if got := b.UpstreamStatus(); got != UpstreamDegraded {
		t.Errorf("expected %q for 10-min-old success, got %q", UpstreamDegraded, got)
	}
}

// TestUpstreamStatusDownAfterLongSilence verifies that a success >30 minutes
// old is reported as "down" — we haven't had recent confirmation ARC works.
func TestUpstreamStatusDownAfterLongSilence(t *testing.T) {
	b := NewBroadcaster(NewMempool(), NewARCClient("https://arc.example.com", ""), slog.Default())
	b.arcLastSuccess.Store(time.Now().Unix() - 3600) // 1 hour ago
	if got := b.UpstreamStatus(); got != UpstreamDown {
		t.Errorf("expected %q for 1-hour-old success, got %q", UpstreamDown, got)
	}
}

// TestUpstreamStatusRecentFailureAfterSuccess verifies that a failure AFTER a
// recent success downgrades to "degraded" (transient issue visible to wallet).
func TestUpstreamStatusRecentFailureAfterSuccess(t *testing.T) {
	b := NewBroadcaster(NewMempool(), NewARCClient("https://arc.example.com", ""), slog.Default())
	now := time.Now().Unix()
	b.arcLastSuccess.Store(now - 60) // 1 min ago
	b.arcLastFailure.Store(now - 10) // 10s ago — newer than success
	if got := b.UpstreamStatus(); got != UpstreamDegraded {
		t.Errorf("expected %q when failure follows success, got %q", UpstreamDegraded, got)
	}
}

// TestUpstreamStatusFailureWithoutAnySuccess verifies "down" when we've only
// ever seen failures — ARC is configured but has never produced a confirmed
// accepted response.
func TestUpstreamStatusFailureWithoutAnySuccess(t *testing.T) {
	b := NewBroadcaster(NewMempool(), NewARCClient("https://arc.example.com", ""), slog.Default())
	b.arcLastFailure.Store(time.Now().Unix() - 5)
	if got := b.UpstreamStatus(); got != UpstreamDown {
		t.Errorf("expected %q when only failures recorded, got %q", UpstreamDown, got)
	}
}
