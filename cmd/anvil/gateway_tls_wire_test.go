package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/gateway"
)

// errorSignalHandler is a slog.Handler that hands every Error-level (or
// higher) record to a test over a channel, instead of counting or
// printing it — used only where the record is produced asynchronously,
// inside a goroutine startGatewayTLS itself starts, so the test has to
// wait for it rather than read it straight off the call stack. The
// channel is buffered so Handle never blocks the logging goroutine on a
// test that's slow to drain it.
type errorSignalHandler struct {
	records chan slog.Record
}

func (h errorSignalHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelError
}
func (h errorSignalHandler) Handle(_ context.Context, r slog.Record) error {
	h.records <- r
	return nil
}
func (h errorSignalHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h errorSignalHandler) WithGroup(string) slog.Handler      { return h }

// capturingHandler keeps the single most recent record it was handed —
// used where the call under test is synchronous, so there is no
// goroutine to race against and a plain pointer write is safe.
type capturingHandler struct {
	record *slog.Record
}

func (h capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h capturingHandler) Handle(_ context.Context, r slog.Record) error {
	*h.record = r
	return nil
}
func (h capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h capturingHandler) WithGroup(string) slog.Handler      { return h }

// recordAttrs flattens a slog.Record's attrs into a map, so a test can
// assert on one key without depending on attr ordering.
func recordAttrs(r slog.Record) map[string]string {
	m := make(map[string]string)
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.String()
		return true
	})
	return m
}

// reserveFreePort binds :0 to let the OS pick a free port, reports its
// address, then releases it immediately — the standard "ask the OS,
// then let something else bind there for real" trick, good enough for a
// test (a reservation held for a handful of milliseconds on a loopback
// address is not a flake source in practice here).
func reserveFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// TestStartGatewayTLS_BindFailureLogsAndContinues occupies the address
// startGatewayTLS is told to bind 443 on, and confirms: the resulting
// bind failure is logged once, as an error, naming the address and the
// underlying cause; startGatewayTLS itself still returns (it never
// blocks on either listener); and the sibling 80 listener — standing in
// for "the mesh and the :9333 API listener keep running", which this
// unit has no access to — binds and accepts a connection regardless,
// proving one listener's bind failure never affects the other's.
func TestStartGatewayTLS_BindFailureLogsAndContinues(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	httpsAddr := occupied.Addr().String()
	httpAddr := reserveFreePort(t)

	cfg := &config.Config{}
	cfg.Node.DataDir = t.TempDir()
	cfg.Gateway.HTTPSListen = httpsAddr
	cfg.Gateway.HTTPListen = httpAddr

	handler := errorSignalHandler{records: make(chan slog.Record, 4)}
	logger := slog.New(handler)

	done := make(chan struct{})
	go func() {
		startGatewayTLS(cfg, nil, &gateway.Router{}, &gateway.Counters{}, nil, logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startGatewayTLS did not return within 5s — it must never block on a listener")
	}

	var rec slog.Record
	select {
	case rec = <-handler.records:
	case <-time.After(5 * time.Second):
		t.Fatal("expected one error log record for the occupied port, got none within 5s")
	}
	if !strings.Contains(rec.Message, "gateway TLS listener stopped") {
		t.Errorf("message = %q, want it to name the TLS listener", rec.Message)
	}
	if got := recordAttrs(rec)["addr"]; got != httpsAddr {
		t.Errorf("addr attr = %q, want %q", got, httpsAddr)
	}

	// The sibling listener on the free port must still come up —
	// confirmed with a bounded poll of a real condition (can we connect
	// to it yet), not a sleep offered as proof.
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", httpAddr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sibling HTTP listener on %s never came up: %v", httpAddr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestStartGatewayTLS_HTTPBindFailureLogsAndContinues mirrors
// TestStartGatewayTLS_BindFailureLogsAndContinues with the occupied and
// free ports swapped, so both listener goroutines' bind-failure path —
// not just the TLS one — is exercised directly by a test, each with its
// own distinct log message.
func TestStartGatewayTLS_HTTPBindFailureLogsAndContinues(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	httpAddr := occupied.Addr().String()
	httpsAddr := reserveFreePort(t)

	cfg := &config.Config{}
	cfg.Node.DataDir = t.TempDir()
	cfg.Gateway.HTTPSListen = httpsAddr
	cfg.Gateway.HTTPListen = httpAddr

	handler := errorSignalHandler{records: make(chan slog.Record, 4)}
	logger := slog.New(handler)

	done := make(chan struct{})
	go func() {
		startGatewayTLS(cfg, nil, &gateway.Router{}, &gateway.Counters{}, nil, logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startGatewayTLS did not return within 5s — it must never block on a listener")
	}

	var rec slog.Record
	select {
	case rec = <-handler.records:
	case <-time.After(5 * time.Second):
		t.Fatal("expected one error log record for the occupied port, got none within 5s")
	}
	if !strings.Contains(rec.Message, "gateway HTTP listener stopped") {
		t.Errorf("message = %q, want it to name the HTTP listener", rec.Message)
	}
	if got := recordAttrs(rec)["addr"]; got != httpAddr {
		t.Errorf("addr attr = %q, want %q", got, httpAddr)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", httpsAddr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sibling TLS listener on %s never came up: %v", httpsAddr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestWarnIfAcmeDirUnwritable_NotYetCreated confirms a directory that
// doesn't exist yet is never reported — building it is NewCache's own
// job, moments before this is called, and a race where it's removed
// again right after is outside what this check can diagnose.
func TestWarnIfAcmeDirUnwritable_NotYetCreated(t *testing.T) {
	dir := t.TempDir() + "/acme-does-not-exist"
	count := 0
	logger := slog.New(countingSlogHandler{count: &count})
	warnIfAcmeDirUnwritable(dir, logger)
	if count != 0 {
		t.Errorf("logged %d record(s) for a directory that doesn't exist yet, want 0", count)
	}
}

// TestWarnIfAcmeDirUnwritable_Writable confirms the common case — a
// fresh or already-correct directory — never logs anything.
func TestWarnIfAcmeDirUnwritable_Writable(t *testing.T) {
	dir := t.TempDir()
	count := 0
	logger := slog.New(countingSlogHandler{count: &count})
	warnIfAcmeDirUnwritable(dir, logger)
	if count != 0 {
		t.Errorf("logged %d record(s) for a writable directory, want 0", count)
	}
}

// TestWarnIfAcmeDirUnwritable_Unwritable confirms a directory that
// exists but can't be written to by this process logs exactly one clear
// error naming the fix — the scenario the spec calls out: left behind by
// an earlier run or an operator, now wrong for the user this process
// runs as.
func TestWarnIfAcmeDirUnwritable_Unwritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory write permission bits; this check can't be exercised as root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0500); err != nil { // read + execute, no write
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700) // restore so t.TempDir()'s cleanup can remove it

	var rec slog.Record
	logger := slog.New(capturingHandler{record: &rec})
	warnIfAcmeDirUnwritable(dir, logger)

	if rec.Message == "" {
		t.Fatal("expected one error record for an unwritable acme directory, got none")
	}
	if !strings.Contains(rec.Message, "cannot write") {
		t.Errorf("message = %q, want it to say this process cannot write to the directory", rec.Message)
	}
	attrs := recordAttrs(rec)
	if attrs["dir"] != dir {
		t.Errorf("dir attr = %q, want %q", attrs["dir"], dir)
	}
	fix := attrs["fix"]
	if !strings.Contains(fix, "chown") || !strings.Contains(fix, "chmod 0700") || !strings.Contains(fix, dir) {
		t.Errorf("fix attr = %q, want it to name chown, chmod 0700, and the directory", fix)
	}
}

// countingSlogHandler counts how many records it was handed, the same
// shape as internal/gateway's own allowlist_test.go countingHandler —
// kept local rather than exported and shared, since this is the first
// place cmd/anvil's own tests have needed it.
type countingSlogHandler struct {
	count *int
}

func (h countingSlogHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h countingSlogHandler) Handle(context.Context, slog.Record) error {
	*h.count++
	return nil
}
func (h countingSlogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h countingSlogHandler) WithGroup(string) slog.Handler      { return h }
